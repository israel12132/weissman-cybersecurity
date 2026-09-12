//! Threat-Informed Board Pack — live findings composed into board PDF + true Excel.
//!
//! Fuses tenant-RLS findings, MITRE exposure, CISA KEV/EPSS, BOD 26-04 triage,
//! FAIR dollars, attack-path snapshots, first-mover surface delta, and leak-engine
//! hits. Empty inputs stay empty. No invented APT names, no dark-web crawl, no PoCs
//! in the board edition.

pub mod bod;
pub mod pdf;
pub mod xlsx;

use crate::attack_coverage;
use crate::attack_exposure::{self, TechniqueStat};
use crate::attack_path;
use crate::financial_risk;
use crate::first_mover_surface_delta;
use bod::BodFactors;
use chrono::TimeZone;
use chrono_tz::Asia::Jerusalem;
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

const LEAK_SOURCES: &[&str] = &[
    "leak_hunter",
    "darkweb_intel",
    "dark_web_monitor",
    "typosquatting_monitor",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PackLang {
    En,
    He,
}

impl PackLang {
    pub fn parse(s: Option<&str>) -> Self {
        match s.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
            Some("he") | Some("he-il") | Some("iw") | Some("hebrew") => PackLang::He,
            _ => PackLang::En,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PackLang::En => "en",
            PackLang::He => "he",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PackFinding {
    pub id: i64,
    pub finding_id: String,
    pub title: String,
    pub severity: String,
    pub source: String,
    pub status: String,
    pub cve: String,
    pub mitre: String,
    pub cvss: Option<f32>,
    pub epss: Option<f32>,
    pub kev_listed: bool,
    pub kev_ransomware: bool,
    pub kev_due: String,
    pub verified: bool,
    pub target: String,
    pub bod: BodFactors,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackPath {
    pub entry: i64,
    pub jewel: i64,
    pub hops: usize,
    pub path_score: u8,
    pub ale_usd: i64,
    pub kev_hops: usize,
    pub mitre_technique_id: String,
    pub root_cause: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BoardPack {
    pub client_id: i64,
    pub client_name: String,
    pub generated_at: String,
    pub lang: PackLang,
    pub findings: Vec<PackFinding>,
    pub techniques: Vec<TechniqueStat>,
    pub paths: Vec<PackPath>,
    pub paths_present: bool,
    pub paths_message: String,
    pub fair_present: bool,
    pub fair_note: String,
    pub ale_usd: i64,
    pub sle_usd: i64,
    pub path_ale_usd: i64,
    pub crown_jewel_usd: i64,
    pub kev_count: usize,
    pub bod_p0: usize,
    pub bod_p1: usize,
    pub leak_count: usize,
    pub first_mover_message: String,
    pub first_mover_added: usize,
    pub first_mover_removed: usize,
    pub first_mover_changed: usize,
    pub first_mover_current: usize,
    pub first_mover_previous: usize,
}

impl BoardPack {
    pub fn empty_demo(client_id: i64, client_name: &str, lang: PackLang) -> Self {
        Self {
            client_id,
            client_name: client_name.to_string(),
            generated_at: israel_now(),
            lang,
            findings: Vec::new(),
            techniques: Vec::new(),
            paths: Vec::new(),
            paths_present: false,
            paths_message: "none yet — honest empty".into(),
            fair_present: false,
            fair_note: "none yet — honest empty".into(),
            ale_usd: 0,
            sle_usd: 0,
            path_ale_usd: 0,
            crown_jewel_usd: 0,
            kev_count: 0,
            bod_p0: 0,
            bod_p1: 0,
            leak_count: 0,
            first_mover_message: "No first-mover snapshot yet — run first_mover_surface_delta."
                .into(),
            first_mover_added: 0,
            first_mover_removed: 0,
            first_mover_changed: 0,
            first_mover_current: 0,
            first_mover_previous: 0,
        }
    }
}

pub fn is_leak_source(source: &str) -> bool {
    let s = source.trim().to_ascii_lowercase();
    LEAK_SOURCES.iter().any(|k| *k == s)
}

fn israel_now() -> String {
    Jerusalem
        .from_utc_datetime(&chrono::Utc::now().naive_utc())
        .format("%Y-%m-%d %H:%M:%S %Z")
        .to_string()
}

fn json_str(v: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(s) = v.get(*k).and_then(Value::as_str) {
            let t = s.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    String::new()
}

fn json_f32(v: &Value, keys: &[&str]) -> Option<f32> {
    for k in keys {
        if let Some(n) = v.get(*k).and_then(Value::as_f64) {
            return Some(n as f32);
        }
        if let Some(s) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = s.parse::<f32>() {
                return Some(n);
            }
        }
    }
    None
}

fn json_bool(v: &Value, keys: &[&str]) -> bool {
    keys.iter()
        .any(|k| v.get(*k).and_then(Value::as_bool).unwrap_or(false))
}

fn techniques_from_raw(raw: &Value) -> String {
    let ids = attack_exposure::techniques_of(raw);
    if !ids.is_empty() {
        return ids.join(",");
    }
    json_str(raw, &["mitre", "mitre_id", "attack_id"])
}

pub async fn compose(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    lang: PackLang,
) -> Result<BoardPack, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let client_name: Option<String> =
        sqlx::query_scalar("SELECT name FROM clients WHERE id = $1 AND tenant_id = $2")
            .bind(client_id)
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
    let client_name = match client_name {
        Some(n) => n,
        None => {
            let _ = tx.rollback().await;
            return Err("client not found".into());
        }
    };
    let rows = sqlx::query(
        r#"SELECT id,
                  COALESCE(finding_id, '') AS finding_id,
                  COALESCE(title, '') AS title,
                  COALESCE(severity, '') AS severity,
                  COALESCE(source, '') AS source,
                  COALESCE(status, 'OPEN') AS status,
                  epss_score,
                  COALESCE(kev_listed, FALSE) AS kev_listed,
                  COALESCE(kev_known_ransomware, FALSE) AS kev_known_ransomware,
                  kev_due_date,
                  COALESCE(raw_data, '{}'::jsonb) AS raw_data
             FROM vulnerabilities
            WHERE tenant_id = $1 AND client_id = $2
            ORDER BY discovered_at DESC NULLS LAST, id DESC
            LIMIT 5000"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;

    let mut findings = Vec::with_capacity(rows.len());
    for r in rows {
        let raw: Value = r.try_get("raw_data").unwrap_or_else(|_| json!({}));
        let source: String = r.try_get("source").unwrap_or_default();
        let severity: String = r.try_get("severity").unwrap_or_default();
        let kev_listed: bool = r.try_get("kev_listed").unwrap_or(false);
        let epss: Option<f32> = r.try_get::<Option<f32>, _>("epss_score").ok().flatten();
        let verified = json_bool(&raw, &["verified", "poc_sealed"])
            || raw
                .get("live_verification")
                .and_then(|v| v.get("verdict"))
                .and_then(Value::as_str)
                .map(|s| s.eq_ignore_ascii_case("confirmed") || s.eq_ignore_ascii_case("verified"))
                .unwrap_or(false);
        let raw_internet = json_bool(
            &raw,
            &["internet_exposed", "public_facing", "internet_facing"],
        ) || json_str(&raw, &["exposure", "exposure_class"])
            .to_ascii_lowercase()
            .contains("internet");
        let cvss = json_f32(&raw, &["cvss", "cvss_score", "cvss_base"]);
        let cve = json_str(&raw, &["cve", "cve_id", "CVE"]);
        let due = r
            .try_get::<Option<chrono::NaiveDate>, _>("kev_due_date")
            .ok()
            .flatten()
            .map(|d| d.to_string())
            .unwrap_or_default();
        let bod = bod::classify(
            &source,
            raw_internet,
            kev_listed,
            epss,
            verified,
            &severity,
            cvss,
        );
        findings.push(PackFinding {
            id: r.try_get("id").unwrap_or(0),
            finding_id: r.try_get("finding_id").unwrap_or_default(),
            title: r.try_get("title").unwrap_or_default(),
            severity,
            source,
            status: r.try_get("status").unwrap_or_default(),
            cve,
            mitre: techniques_from_raw(&raw),
            cvss,
            epss,
            kev_listed,
            kev_ransomware: r.try_get("kev_known_ransomware").unwrap_or(false),
            kev_due: due,
            verified,
            target: json_str(&raw, &["target", "host", "asset", "url"]),
            bod,
        });
    }

    let techniques = match attack_exposure::load_exposure(pool, tenant_id, client_id, 2000).await {
        Ok(t) => t,
        Err(e) => {
            return Err(format!("ATT&CK exposure unavailable: {e}"));
        }
    };
    // Touch catalog so unmapped tactics stay honest.
    let _ = attack_coverage::lookup("T1190");

    let (paths, paths_present, paths_message, path_ale_from_graph) =
        match attack_path::latest_snapshot(pool, tenant_id, client_id).await {
            Ok(Some(s)) => {
                let rows: Vec<PackPath> = s
                    .paths
                    .iter()
                    .take(40)
                    .map(|p| PackPath {
                        entry: p.entry,
                        jewel: p.jewel,
                        hops: p.hops,
                        path_score: p.path_score,
                        ale_usd: p.ale_usd,
                        kev_hops: p.kev_hops,
                        mitre_technique_id: p.mitre_technique_id.clone(),
                        root_cause: p.root_cause.clone(),
                    })
                    .collect();
                (
                    rows,
                    true,
                    format!(
                        "Live Dijkstra snapshot: {} paths, max score {}, {} choke-points, graph_dirty={}.",
                        s.paths.len(),
                        s.max_path_score,
                        s.choke_points.len(),
                        s.graph_dirty
                    ),
                    s.total_path_ale_usd,
                )
            }
            Ok(None) => (
                Vec::new(),
                false,
                "No attack-path snapshot yet — run attack-path inference or supreme_path_fair_rag."
                    .into(),
                0,
            ),
            Err(e) => (
                Vec::new(),
                false,
                format!("Attack-path snapshot unavailable: {e}"),
                0,
            ),
        };

    let (fair_present, fair_note, ale_usd, sle_usd, crown_jewel_usd, path_ale_usd) =
        match financial_risk::latest_snapshot(pool, tenant_id, client_id).await {
            Ok(Some(s)) => (
                true,
                "Live FAIR snapshot (asset value x CVSS/EPSS, KEV floors rate).".into(),
                s.ale_annualised_usd,
                s.sle_worst_usd,
                s.crown_jewel_value_usd,
                if s.path_ale_usd > 0 {
                    s.path_ale_usd
                } else {
                    path_ale_from_graph
                },
            ),
            Ok(None) => (
                false,
                "No FAIR snapshot yet — open Financial Blast-Radius and compute.".into(),
                0,
                0,
                0,
                path_ale_from_graph,
            ),
            Err(e) => (
                false,
                format!("FAIR snapshot unavailable: {e}"),
                0,
                0,
                0,
                path_ale_from_graph,
            ),
        };

    let mut first_mover_message =
        "No first-mover snapshot yet — run first_mover_surface_delta against an authorized domain."
            .to_string();
    let mut first_mover_added = 0usize;
    let mut first_mover_removed = 0usize;
    let mut first_mover_changed = 0usize;
    let mut first_mover_current = 0usize;
    let mut first_mover_previous = 0usize;
    match first_mover_surface_delta::api_surface_diff_json(pool, tenant_id, client_id).await {
        Ok(diff) => {
            if let Some(msg) = diff.get("message").and_then(Value::as_str) {
                if !msg.is_empty() {
                    first_mover_message = msg.to_string();
                }
            }
            first_mover_added = diff
                .get("added")
                .and_then(Value::as_array)
                .map(|a| a.len())
                .unwrap_or(0);
            first_mover_removed = diff
                .get("removed")
                .and_then(Value::as_array)
                .map(|a| a.len())
                .unwrap_or(0);
            first_mover_changed = diff
                .get("changed")
                .and_then(Value::as_array)
                .map(|a| a.len())
                .unwrap_or(0);
            first_mover_current = diff
                .get("current_count")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            first_mover_previous = diff
                .get("previous_count")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            if first_mover_added + first_mover_removed + first_mover_changed > 0 {
                first_mover_message = format!(
                    "Live surface delta: +{first_mover_added} / -{first_mover_removed} / ~{first_mover_changed} hosts."
                );
            }
        }
        Err(e) => {
            first_mover_message = format!("First-mover snapshot unavailable: {e}");
        }
    }

    let kev_count = findings.iter().filter(|f| f.kev_listed).count();
    let bod_p0 = findings
        .iter()
        .filter(|f| f.bod.tier() == bod::BodTier::P0)
        .count();
    let bod_p1 = findings
        .iter()
        .filter(|f| f.bod.tier() == bod::BodTier::P1)
        .count();
    let leak_count = findings
        .iter()
        .filter(|f| is_leak_source(&f.source))
        .count();

    Ok(BoardPack {
        client_id,
        client_name,
        generated_at: israel_now(),
        lang,
        findings,
        techniques,
        paths,
        paths_present,
        paths_message,
        fair_present,
        fair_note,
        ale_usd,
        sle_usd,
        path_ale_usd,
        crown_jewel_usd,
        kev_count,
        bod_p0,
        bod_p1,
        leak_count,
        first_mover_message,
        first_mover_added,
        first_mover_removed,
        first_mover_changed,
        first_mover_current,
        first_mover_previous,
    })
}

pub fn preview_json(pack: &BoardPack) -> Value {
    json!({
        "ok": true,
        "client_id": pack.client_id,
        "client_name": pack.client_name,
        "generated_at": pack.generated_at,
        "lang": pack.lang.as_str(),
        "live_only": true,
        "kpis": {
            "findings": pack.findings.len(),
            "kev_listed": pack.kev_count,
            "bod_p0": pack.bod_p0,
            "bod_p1": pack.bod_p1,
            "ale_usd": pack.ale_usd,
            "sle_usd": pack.sle_usd,
            "path_ale_usd": pack.path_ale_usd,
            "crown_jewel_usd": pack.crown_jewel_usd,
            "techniques": pack.techniques.len(),
            "attack_paths": pack.paths.len(),
            "leak_findings": pack.leak_count,
            "first_mover_added": pack.first_mover_added,
            "first_mover_removed": pack.first_mover_removed,
            "fair_present": pack.fair_present,
            "paths_present": pack.paths_present,
        },
        "paths_message": pack.paths_message,
        "fair_note": pack.fair_note,
        "first_mover_message": pack.first_mover_message,
        "top_techniques": pack.techniques.iter().take(12).collect::<Vec<_>>(),
        "top_paths": pack.paths.iter().take(8).collect::<Vec<_>>(),
        "p0_findings": pack.findings.iter().filter(|f| f.bod.tier() == bod::BodTier::P0).take(12).collect::<Vec<_>>(),
        "sources": [
            "CISA BOD 26-04",
            "CISA KEV",
            "FIRST EPSS (automatable proxy)",
            "MITRE ATT&CK",
            "tenant-RLS findings",
        ],
        "downloads": {
            "pdf": format!("/api/clients/{}/board-pack/pdf?lang={}", pack.client_id, pack.lang.as_str()),
            "xlsx": format!("/api/clients/{}/board-pack/xlsx?lang={}", pack.client_id, pack.lang.as_str()),
        }
    })
}

pub fn safe_filename(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let s = s.trim_matches('_');
    if s.is_empty() {
        "client".into()
    } else {
        s.chars().take(48).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leak_sources_are_explicit() {
        assert!(is_leak_source("leak_hunter"));
        assert!(is_leak_source("Dark_Web_Monitor"));
        assert!(!is_leak_source("asm"));
    }

    #[test]
    fn lang_parse() {
        assert_eq!(PackLang::parse(Some("he")), PackLang::He);
        assert_eq!(PackLang::parse(Some("EN")), PackLang::En);
        assert_eq!(PackLang::parse(None), PackLang::En);
    }

    #[test]
    fn preview_marks_empty_honestly() {
        let p = BoardPack::empty_demo(3, "Demo", PackLang::En);
        let v = preview_json(&p);
        assert_eq!(v["ok"], true);
        assert_eq!(v["kpis"]["findings"], 0);
        assert_eq!(v["kpis"]["fair_present"], false);
        assert!(
            v["fair_note"].as_str().unwrap().contains("honest empty")
                || v["fair_note"].as_str().unwrap().contains("none yet")
        );
    }
}
