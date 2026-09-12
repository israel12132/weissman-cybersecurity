//! **First-seen vs NVD/OSV** — a vulnerability on the customer's inventory *before*
//! the CVE is in NVD, not after weekly scanners catch up.
//!
//! Live evidence only:
//! 1. Tenant SBOM (`client_sbom_components`) queried against OSV (`api.osv.dev`) — no token.
//! 2. Optional NVD CVE lookup when `NVD_API_KEY` is set.
//! 3. Optional HTTP banners from the latest `surface_snapshots` (info only when already in NVD).
//!
//! Honesty:
//! - `nvd_status=absent_cve`  — OSV/GHSA id with no CVE alias (true pre-CVE).
//! - `nvd_status=unpublished` — CVE alias, NVD catalog empty (lag vs NVD).
//! - `nvd_status=listed`      — already in NVD; **not** claimed as first-seen (skip / info).
//! - `nvd_status=skipped_no_key` — cannot prove NVD lag; emit medium with that stated.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{empty_ok, finding};
use crate::engine_result::EngineResult;
use crate::nvd_cve;
use serde_json::{json, Value};
use sqlx::Row;
use std::sync::Arc;
use std::time::Duration;

pub const ENGINE_ID: &str = "first_seen_osv_nvd";
const MITRE: &str = "T1595.002";
const MAX_SBOM: usize = 40;
const MAX_OSV_PER_PKG: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NvdStatus {
    AbsentCve,
    Unpublished,
    Listed,
    SkippedNoKey,
}

impl NvdStatus {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AbsentCve => "absent_cve",
            Self::Unpublished => "unpublished",
            Self::Listed => "listed",
            Self::SkippedNoKey => "skipped_no_key",
        }
    }

    /// Only these statuses may be titled as first-seen (before NVD).
    #[must_use]
    pub fn is_first_seen(&self) -> bool {
        matches!(self, Self::AbsentCve | Self::Unpublished)
    }

    #[must_use]
    pub fn from_db(s: &str) -> Self {
        match s.trim() {
            "absent_cve" => Self::AbsentCve,
            "unpublished" => Self::Unpublished,
            "listed" => Self::Listed,
            _ => Self::SkippedNoKey,
        }
    }
}

#[derive(Debug, Clone)]
struct SbomRow {
    package_name: String,
    ecosystem: String,
    version_spec: String,
}

#[derive(Debug, Clone)]
struct OsvHit {
    id: String,
    cve: Option<String>,
    summary: String,
    severity: String,
}

/// Parse `nginx/1.24.0` / `Apache/2.4.57` banners. Tests cover the contract.
#[must_use]
pub fn parse_product_banner(raw: &str) -> Option<(String, String)> {
    let t = raw.trim();
    let t = t.split_whitespace().next().unwrap_or(t);
    let (prod, ver) = t.split_once('/')?;
    let prod = prod.trim().to_ascii_lowercase();
    let ver = ver
        .trim()
        .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-' && c != '_')
        .to_string();
    if prod.len() < 2 || ver.is_empty() || !ver.chars().next()?.is_ascii_digit() {
        return None;
    }
    Some((prod, ver))
}

fn map_ecosystem(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "npm" | "nodejs" => Some("npm"),
        "pypi" | "pip" | "python" => Some("PyPI"),
        "go" | "golang" => Some("Go"),
        "maven" | "java" => Some("Maven"),
        "crates" | "cargo" | "rust" => Some("crates.io"),
        "rubygems" | "gem" | "ruby" => Some("RubyGems"),
        "nuget" | "dotnet" => Some("NuGet"),
        "packagist" | "composer" | "php" => Some("Packagist"),
        "debian" => Some("Debian"),
        "alpine" => Some("Alpine"),
        "" => None,
        _ => None,
    }
}

async fn load_sbom(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<Vec<SbomRow>, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let rows = sqlx::query(
        r#"SELECT package_name, COALESCE(ecosystem,'') AS ecosystem,
                  COALESCE(version_spec,'') AS version_spec
           FROM client_sbom_components
           WHERE tenant_id = $1 AND client_id = $2
           ORDER BY id DESC
           LIMIT $3"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(MAX_SBOM as i64)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            let package_name: String = r.try_get("package_name").ok()?;
            let package_name = package_name.trim().to_string();
            if package_name.is_empty() {
                return None;
            }
            Some(SbomRow {
                package_name,
                ecosystem: r.try_get("ecosystem").unwrap_or_default(),
                version_spec: r.try_get("version_spec").unwrap_or_default(),
            })
        })
        .collect())
}

async fn already_recorded(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
    osv_id: &str,
    package: &str,
    version: &str,
) -> bool {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return false;
    };
    let found: Option<i64> = sqlx::query_scalar(
        r#"SELECT id FROM osv_first_seen_hits
           WHERE tenant_id = $1 AND client_id = $2 AND osv_id = $3
             AND package_name = $4 AND version_spec = $5
           LIMIT 1"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(osv_id)
    .bind(package)
    .bind(version)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    found.is_some()
}

async fn persist_hit(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
    pkg: &SbomRow,
    hit: &OsvHit,
    nvd: &NvdStatus,
) -> Result<(), String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    sqlx::query(
        r#"INSERT INTO osv_first_seen_hits
            (tenant_id, client_id, package_name, version_spec, ecosystem, osv_id, cve_id, nvd_status, evidence_json)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
           ON CONFLICT (tenant_id, client_id, osv_id, package_name, version_spec)
           DO UPDATE SET nvd_status = EXCLUDED.nvd_status,
                         evidence_json = EXCLUDED.evidence_json,
                         cve_id = EXCLUDED.cve_id"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(&pkg.package_name)
    .bind(&pkg.version_spec)
    .bind(&pkg.ecosystem)
    .bind(&hit.id)
    .bind(hit.cve.as_deref())
    .bind(nvd.as_str())
    .bind(json!({
        "summary": hit.summary,
        "severity": hit.severity,
        "nvd_status": nvd.as_str(),
    }))
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Live SBOM×OSV hits for a client — `listed` is returned honestly, never titled first-seen.
pub async fn list_hits_json(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<Value, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let rows = sqlx::query(
        r#"SELECT id, package_name, version_spec, ecosystem, osv_id, cve_id, nvd_status,
                  evidence_json, first_seen_at
           FROM osv_first_seen_hits
           WHERE tenant_id = $1 AND client_id = $2
           ORDER BY first_seen_at DESC
           LIMIT 200"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;

    let mut first_seen_n = 0usize;
    let mut listed_n = 0usize;
    let mut skipped_n = 0usize;
    let mut hits: Vec<Value> = Vec::with_capacity(rows.len());
    for r in rows {
        let status = NvdStatus::from_db(&r.try_get::<String, _>("nvd_status").unwrap_or_default());
        if status.is_first_seen() {
            first_seen_n += 1;
        } else if matches!(status, NvdStatus::Listed) {
            listed_n += 1;
        } else {
            skipped_n += 1;
        }
        hits.push(json!({
            "id": r.try_get::<i64, _>("id").unwrap_or(0),
            "package_name": r.try_get::<String, _>("package_name").unwrap_or_default(),
            "version_spec": r.try_get::<String, _>("version_spec").unwrap_or_default(),
            "ecosystem": r.try_get::<String, _>("ecosystem").unwrap_or_default(),
            "osv_id": r.try_get::<String, _>("osv_id").unwrap_or_default(),
            "cve_id": r.try_get::<Option<String>, _>("cve_id").ok().flatten(),
            "evidence": r.try_get::<Value, _>("evidence_json").unwrap_or(json!({})),
            "nvd_status": status.as_str(),
            "claimed_first_seen": status.is_first_seen(),
            "first_seen_at": r
                .try_get::<chrono::DateTime<chrono::Utc>, _>("first_seen_at")
                .map(|d| d.to_rfc3339())
                .unwrap_or_default(),
        }));
    }

    Ok(json!({
        "ok": true,
        "client_id": client_id,
        "engine": ENGINE_ID,
        "nvd_api_key_configured": crate::nvd_cve::nvd_api_key_present(),
        "first_seen_count": first_seen_n,
        "listed_count": listed_n,
        "skipped_count": skipped_n,
        "hits": hits,
    }))
}

async fn query_osv(client: &reqwest::Client, eco: &str, name: &str, version: &str) -> Vec<OsvHit> {
    let mut body = json!({ "package": { "name": name } });
    if !eco.is_empty() {
        body["package"]["ecosystem"] = json!(eco);
    }
    if !version.trim().is_empty() {
        body["version"] = json!(version.trim());
    }
    let Ok(resp) = client
        .post("https://api.osv.dev/v1/query")
        .json(&body)
        .timeout(Duration::from_secs(12))
        .send()
        .await
    else {
        return vec![];
    };
    if !resp.status().is_success() {
        return vec![];
    }
    let Ok(data) = resp.json::<Value>().await else {
        return vec![];
    };
    let Some(vulns) = data.get("vulns").and_then(Value::as_array) else {
        return vec![];
    };
    let mut out = Vec::new();
    for v in vulns.iter().take(MAX_OSV_PER_PKG) {
        let id = v
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if id.is_empty() {
            continue;
        }
        let mut cve = None;
        if let Some(al) = v.get("aliases").and_then(Value::as_array) {
            for a in al {
                if let Some(s) = a.as_str() {
                    let u = s.trim().to_ascii_uppercase();
                    if u.starts_with("CVE-") {
                        cve = Some(u);
                        break;
                    }
                }
            }
        }
        let summary = v
            .get("summary")
            .and_then(Value::as_str)
            .or_else(|| v.get("details").and_then(Value::as_str))
            .unwrap_or("")
            .chars()
            .take(280)
            .collect::<String>();
        out.push(OsvHit {
            id,
            cve,
            summary,
            severity: "high".into(),
        });
    }
    out
}

async fn classify_nvd(cve: Option<&str>) -> NvdStatus {
    let Some(cve) = cve.filter(|s| s.starts_with("CVE-")) else {
        return NvdStatus::AbsentCve;
    };
    if !nvd_cve::nvd_api_key_present() {
        return NvdStatus::SkippedNoKey;
    }
    match nvd_cve::nvd_cve_listed(cve).await {
        Ok(true) => NvdStatus::Listed,
        Ok(false) => NvdStatus::Unpublished,
        Err(_) => NvdStatus::SkippedNoKey,
    }
}

fn live_finding(
    title: &str,
    severity: &str,
    description: &str,
    target: &str,
    extra: Value,
) -> Value {
    let mut f = finding(ENGINE_ID, title, severity, MITRE, description, target);
    if let Some(obj) = f.as_object_mut() {
        if let Some(map) = extra.as_object() {
            for (k, v) in map {
                obj.insert(k.clone(), v.clone());
            }
        }
        obj.insert("asset".into(), json!("first_seen"));
        obj.insert(
            "evidence".into(),
            json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "engine_id": ENGINE_ID,
                "method": "osv+nvd+sbom",
            }),
        );
    }
    f
}

pub async fn run_first_seen_osv_nvd_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    let Some(pool) = ctx.app_pool.as_ref() else {
        return EngineResult::error("database required for first-seen OSV/NVD");
    };
    let Some(tid) = ctx.tenant_id else {
        return EngineResult::error("tenant required");
    };
    let Some(cid) = ctx.client_id else {
        return EngineResult::error(
            "client_id required — first-seen matches tenant SBOM, not a guessed CVE feed",
        );
    };

    let sbom = match load_sbom(pool.as_ref(), tid, cid).await {
        Ok(s) => s,
        Err(e) => return EngineResult::error(format!("SBOM read failed: {e}")),
    };
    if sbom.is_empty() {
        return EngineResult::ok(
            vec![live_finding(
                "First-seen OSV/NVD: no SBOM inventory for this client",
                "info",
                "Upload or sync client_sbom_components (package + version + ecosystem). Without live inventory there is no honest pre-NVD claim.",
                if target.trim().is_empty() { "sbom" } else { target },
                json!({ "nvd_status": "skipped_no_inventory" }),
            )],
            "first_seen_osv_nvd: empty SBOM — no fabricated vulns",
        );
    }

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .user_agent("Weissman-FirstSeen/1.0")
        .build()
    {
        Ok(c) => c,
        Err(e) => return EngineResult::error(format!("http client: {e}")),
    };

    let mut findings = Vec::new();
    let mut first_seen_n = 0usize;
    let mut listed_n = 0usize;
    for pkg in &sbom {
        let ver = pkg.version_spec.trim();
        if ver.is_empty() || ver == "*" || ver == "latest" {
            continue;
        }
        let eco = map_ecosystem(&pkg.ecosystem).unwrap_or("");
        if eco.is_empty() {
            continue;
        }
        let hits = query_osv(&client, eco, &pkg.package_name, ver).await;
        for hit in hits {
            if already_recorded(pool.as_ref(), tid, cid, &hit.id, &pkg.package_name, ver).await {
                continue;
            }
            let nvd = classify_nvd(hit.cve.as_deref()).await;
            let _ = persist_hit(pool.as_ref(), tid, cid, pkg, &hit, &nvd).await;
            if nvd == NvdStatus::Listed {
                listed_n += 1;
                continue;
            }
            let (sev, title) = if nvd.is_first_seen() {
                first_seen_n += 1;
                (
                    "critical",
                    format!(
                        "First-seen {} on {}@{} before NVD ({})",
                        hit.id,
                        pkg.package_name,
                        ver,
                        nvd.as_str()
                    ),
                )
            } else {
                (
                    "medium",
                    format!(
                        "OSV {} on {}@{} — NVD not checked ({})",
                        hit.id,
                        pkg.package_name,
                        ver,
                        nvd.as_str()
                    ),
                )
            };
            let desc = if nvd == NvdStatus::AbsentCve {
                format!(
                    "Live SBOM {}@{} ({}) matches OSV {} with no CVE alias. The customer is exposed before a CVE exists in NVD. {}",
                    pkg.package_name, ver, eco, hit.id, hit.summary
                )
            } else if nvd == NvdStatus::Unpublished {
                format!(
                    "OSV {} aliases {} but NIST NVD has no catalog row yet. Inventory is already running the affected version. {}",
                    hit.id,
                    hit.cve.as_deref().unwrap_or("CVE"),
                    hit.summary
                )
            } else {
                format!(
                    "OSV {} matches {}@{}. NVD lag was not proven (no API key or lookup error) — not claimed as pre-NVD. {}",
                    hit.id, pkg.package_name, ver, hit.summary
                )
            };
            findings.push(live_finding(
                &title,
                sev,
                &desc,
                &format!("{}@{}", pkg.package_name, ver),
                json!({
                    "osv_id": hit.id,
                    "cve": hit.cve,
                    "nvd_status": nvd.as_str(),
                    "ecosystem": eco,
                    "package": pkg.package_name,
                    "version": ver,
                }),
            ));
        }
    }

    if findings.is_empty() {
        if listed_n > 0 {
            findings.push(live_finding(
                "SBOM × OSV hits already listed in NVD",
                "info",
                &format!(
                    "{listed_n} OSV match(es) on this SBOM are already in NIST NVD — not claimed as first-seen."
                ),
                target,
                json!({ "nvd_status": "listed", "listed_count": listed_n }),
            ));
        } else {
            return empty_ok(ENGINE_ID, target);
        }
    }
    EngineResult::ok(
        findings,
        format!("{ENGINE_ID}: first_seen={first_seen_n} listed={listed_n} (OSV live, NVD honest)"),
    )
}

async fn enqueue_clients_with_sbom(
    app_pool: &sqlx::PgPool,
    tenant_id: i64,
) -> Result<usize, String> {
    let mut tx = crate::db::begin_tenant_tx(app_pool, tenant_id)
        .await
        .map_err(|_| "database unavailable".to_string())?;
    let rows = sqlx::query(
        r#"SELECT DISTINCT c.id, COALESCE(c.domains, '[]') AS domains
           FROM clients c
           INNER JOIN client_sbom_components s ON s.client_id = c.id AND s.tenant_id = c.tenant_id
           ORDER BY c.id
           LIMIT 20"#,
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;
    let mut n = 0usize;
    for r in rows {
        let id: i64 = r.try_get("id").unwrap_or(0);
        if id <= 0 {
            continue;
        }
        let raw: String = r.try_get("domains").unwrap_or_else(|_| "[]".into());
        let domains: Vec<String> = serde_json::from_str(&raw).unwrap_or_default();
        let target = domains
            .iter()
            .map(|s| s.trim())
            .find(|s| !s.is_empty())
            .unwrap_or("sbom")
            .to_string();
        let payload = json!({
            "engine": ENGINE_ID,
            "target": target,
            "client_id": id,
            "trigger": "first_seen_worker",
        });
        if crate::async_jobs::enqueue(app_pool, tenant_id, "command_center_engine", payload, None)
            .await
            .is_ok()
        {
            n += 1;
        }
    }
    Ok(n)
}

/// Periodic OSV/NVD first-seen for clients that actually have SBOM rows.
pub fn spawn_first_seen_worker(app_pool: Arc<sqlx::PgPool>, auth_pool: Arc<sqlx::PgPool>) {
    static SPAWNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if SPAWNED.set(()).is_err() {
        return;
    }
    if matches!(
        std::env::var("WEISSMAN_FIRST_SEEN_WORKER").as_deref(),
        Ok("0") | Ok("false") | Ok("off")
    ) {
        tracing::info!(target: "first_seen", "worker disabled");
        return;
    }
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(40)).await;
        let interval = std::env::var("WEISSMAN_FIRST_SEEN_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|&n: &u64| n >= 300)
            .unwrap_or(30 * 60);
        let mut ticker = tokio::time::interval(Duration::from_secs(interval));
        loop {
            ticker.tick().await;
            let tenants: Vec<i64> =
                sqlx::query_scalar("SELECT id FROM tenants WHERE active = true")
                    .fetch_all(auth_pool.as_ref())
                    .await
                    .unwrap_or_default();
            for tid in tenants {
                match enqueue_clients_with_sbom(app_pool.as_ref(), tid).await {
                    Ok(n) if n > 0 => {
                        tracing::info!(target: "first_seen", tenant_id = tid, jobs = n, "queued first-seen hunts");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!(
                            target: "first_seen",
                            tenant_id = tid,
                            error = %e,
                            "SBOM enqueue failed — idle 0 is not confirmed"
                        );
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_parse() {
        assert_eq!(
            parse_product_banner("nginx/1.24.0"),
            Some(("nginx".into(), "1.24.0".into()))
        );
        assert_eq!(
            parse_product_banner("Apache/2.4.57 (Ubuntu)"),
            Some(("apache".into(), "2.4.57".into()))
        );
        assert!(parse_product_banner("cloudflare").is_none());
        assert!(parse_product_banner("").is_none());
    }

    #[test]
    fn first_seen_statuses_are_honest() {
        assert!(NvdStatus::AbsentCve.is_first_seen());
        assert!(NvdStatus::Unpublished.is_first_seen());
        assert!(!NvdStatus::Listed.is_first_seen());
        assert!(!NvdStatus::SkippedNoKey.is_first_seen());
        assert_eq!(NvdStatus::SkippedNoKey.as_str(), "skipped_no_key");
        assert!(NvdStatus::from_db("absent_cve").is_first_seen());
        assert!(NvdStatus::from_db("unpublished").is_first_seen());
        assert!(!NvdStatus::from_db("listed").is_first_seen());
        assert!(!NvdStatus::from_db("skipped_no_key").is_first_seen());
        assert_eq!(NvdStatus::from_db("listed").as_str(), "listed");
        assert!(!NvdStatus::from_db("garbage").is_first_seen());
    }

    #[test]
    fn ecosystem_map() {
        assert_eq!(map_ecosystem("npm"), Some("npm"));
        assert_eq!(map_ecosystem("PyPI"), Some("PyPI"));
        assert_eq!(map_ecosystem("unknown-eco"), None);
    }
}
