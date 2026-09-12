//! Weissman Dominion Board Pack — live findings + FAIR + attack paths + leak intel
//! fused into JSON + real XLSX. Never invents findings.

use crate::xlsx_workbook::{build_xlsx, Cell, Sheet};
use chrono::{TimeZone, Utc};
use chrono_tz::Asia::Jerusalem;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const LEAK_SOURCES: &[&str] = &[
    "leak_hunter",
    "darkweb_intel",
    "dark_web_monitor",
    "typosquatting_monitor",
    "dominion_fusion",
    "public_leak_osint",
];

#[derive(Debug, Clone, Serialize)]
pub struct DominionFinding {
    pub id: i64,
    pub title: String,
    pub severity: String,
    pub source: String,
    pub status: String,
    pub discovered_at: String,
    pub has_proof: bool,
    pub kev_listed: bool,
    pub epss_score: f32,
    pub remediation: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DominionKpis {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub kev: usize,
    pub leak: usize,
    pub with_proof: usize,
    pub engines: usize,
    pub open: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DominionPack {
    pub ok: bool,
    pub live: bool,
    pub client_id: i64,
    pub client_name: String,
    pub generated_at: String,
    pub pack_sha256: String,
    pub grade: String,
    pub grade_reason: String,
    pub kpis: DominionKpis,
    pub financial: Option<Value>,
    pub attack_paths: Option<Value>,
    pub crypto_proof: Option<Value>,
    pub findings: Vec<DominionFinding>,
    pub downloads: Value,
}

#[derive(Debug, Clone)]
pub struct DominionFindingInput {
    pub id: i64,
    pub title: String,
    pub severity: String,
    pub source: String,
    pub status: String,
    pub discovered_at: String,
    pub description: String,
    pub poc_exploit: String,
    pub proof: String,
    pub kev_listed: bool,
    pub epss_score: f32,
}

pub fn is_leak_source(source: &str) -> bool {
    let s = source.trim().to_ascii_lowercase();
    LEAK_SOURCES.iter().any(|x| *x == s)
}

pub fn severity_bucket(sev: &str) -> &'static str {
    let s = sev.to_ascii_lowercase();
    if s.contains("crit") {
        "critical"
    } else if s.contains("high") {
        "high"
    } else if s.contains("med") {
        "medium"
    } else if s.contains("low") {
        "low"
    } else {
        "info"
    }
}

pub fn board_grade(k: &DominionKpis) -> (&'static str, String) {
    if k.total == 0 {
        return (
            "NO LEDGER",
            "No live findings in the tenant ledger. Run an authorized scan — this is not a clean bill of health.".into(),
        );
    }
    if k.kev > 0 || k.critical > 0 {
        return (
            "P0 — BOARD ACTION",
            format!(
                "{} critical, {} KEV-listed, {} leak-intel hits. Board-level containment this week.",
                k.critical, k.kev, k.leak
            ),
        );
    }
    if k.high > 0 || k.leak > 0 {
        return (
            "P1 — EXECUTIVE WATCH",
            format!(
                "{} high, {} leak-intel, {} with proof. Fix in the current sprint.",
                k.high, k.leak, k.with_proof
            ),
        );
    }
    (
        "P2 — TRACKED",
        format!(
            "{} live findings, {} with proof. Continue continuous scan and remediation SLAs.",
            k.total, k.with_proof
        ),
    )
}

fn remediation_from_desc(desc: &str) -> String {
    let desc = desc.trim();
    if desc.is_empty() {
        return String::new();
    }
    if let Ok(v) = serde_json::from_str::<Value>(desc) {
        for key in ["remediation_snippet", "remediation"] {
            if let Some(s) = v.get(key).and_then(|x| x.as_str()) {
                if !s.is_empty() {
                    return s.to_string();
                }
            }
        }
    }
    String::new()
}

pub fn build_pack(
    client_id: i64,
    client_name: &str,
    rows: Vec<DominionFindingInput>,
    financial: Option<Value>,
    attack_paths: Option<Value>,
    crypto_proof: Option<Value>,
) -> DominionPack {
    let mut kpis = DominionKpis::default();
    let mut engines = std::collections::BTreeSet::new();
    let mut findings = Vec::with_capacity(rows.len().min(500));
    for r in rows {
        let bucket = severity_bucket(&r.severity);
        kpis.total += 1;
        match bucket {
            "critical" => kpis.critical += 1,
            "high" => kpis.high += 1,
            "medium" => kpis.medium += 1,
            "low" => kpis.low += 1,
            _ => {}
        }
        if r.kev_listed {
            kpis.kev += 1;
        }
        if is_leak_source(&r.source) {
            kpis.leak += 1;
        }
        let has_proof = !r.poc_exploit.trim().is_empty() || !r.proof.trim().is_empty();
        if has_proof {
            kpis.with_proof += 1;
        }
        if r.status.to_ascii_lowercase() == "open" || r.status.is_empty() {
            kpis.open += 1;
        }
        if !r.source.trim().is_empty() {
            engines.insert(r.source.to_ascii_lowercase());
        }
        findings.push(DominionFinding {
            id: r.id,
            title: r.title,
            severity: r.severity,
            source: r.source,
            status: r.status,
            discovered_at: r.discovered_at,
            has_proof,
            kev_listed: r.kev_listed,
            epss_score: r.epss_score,
            remediation: remediation_from_desc(&r.description),
        });
    }
    kpis.engines = engines.len();
    let (grade, grade_reason) = board_grade(&kpis);
    let generated_at = Jerusalem
        .from_utc_datetime(&Utc::now().naive_utc())
        .format("%Y-%m-%d %H:%M:%S %Z")
        .to_string();
    let mut pack = DominionPack {
        ok: true,
        live: true,
        client_id,
        client_name: client_name.to_string(),
        generated_at,
        pack_sha256: String::new(),
        grade: grade.to_string(),
        grade_reason,
        kpis,
        financial,
        attack_paths,
        crypto_proof,
        findings,
        downloads: json!({
            "pdf": format!("/api/clients/{client_id}/report/pdf"),
            "xlsx": format!("/api/clients/{client_id}/report/xlsx"),
            "csv": format!("/api/clients/{client_id}/export/csv"),
        }),
    };
    let hash_input = serde_json::to_vec(&json!({
        "client_id": pack.client_id,
        "client_name": pack.client_name,
        "grade": pack.grade,
        "kpis": pack.kpis,
        "finding_ids": pack.findings.iter().map(|f| f.id).collect::<Vec<_>>(),
        "audit": pack.crypto_proof,
    }))
    .unwrap_or_default();
    pack.pack_sha256 = hex::encode(Sha256::digest(&hash_input));
    pack
}

pub fn pack_to_xlsx(pack: &DominionPack) -> Result<Vec<u8>, String> {
    let mut exec_rows = vec![
        vec![Cell::from("Weissman Dominion Board Pack"), Cell::from(pack.client_name.as_str())],
        vec![Cell::from("Generated (Israel)"), Cell::from(pack.generated_at.as_str())],
        vec![Cell::from("Grade"), Cell::from(pack.grade.as_str())],
        vec![Cell::from("Grade reason"), Cell::from(pack.grade_reason.as_str())],
        vec![Cell::from("Pack SHA-256"), Cell::from(pack.pack_sha256.as_str())],
        vec![Cell::from("Live"), Cell::from(if pack.live { "true" } else { "false" })],
        vec![Cell::Empty],
        vec![Cell::from("KPI"), Cell::from("Value")],
        vec![Cell::from("Total findings"), Cell::from(pack.kpis.total as i64)],
        vec![Cell::from("Critical"), Cell::from(pack.kpis.critical as i64)],
        vec![Cell::from("High"), Cell::from(pack.kpis.high as i64)],
        vec![Cell::from("Medium"), Cell::from(pack.kpis.medium as i64)],
        vec![Cell::from("KEV listed"), Cell::from(pack.kpis.kev as i64)],
        vec![Cell::from("Leak / dark-web intel"), Cell::from(pack.kpis.leak as i64)],
        vec![Cell::from("With proof"), Cell::from(pack.kpis.with_proof as i64)],
        vec![Cell::from("Engines"), Cell::from(pack.kpis.engines as i64)],
        vec![Cell::from("Open"), Cell::from(pack.kpis.open as i64)],
    ];
    if let Some(fin) = &pack.financial {
        exec_rows.push(vec![Cell::Empty]);
        exec_rows.push(vec![Cell::from("FAIR ALE USD"), Cell::from(fin.get("ale_annualised_usd").and_then(|x| x.as_i64()).unwrap_or(0))]);
        exec_rows.push(vec![Cell::from("FAIR SLE USD"), Cell::from(fin.get("sle_worst_usd").and_then(|x| x.as_i64()).unwrap_or(0))]);
        exec_rows.push(vec![Cell::from("Crown-jewel USD"), Cell::from(fin.get("crown_jewel_value_usd").and_then(|x| x.as_i64()).unwrap_or(0))]);
    }
    if let Some(hash) = pack
        .crypto_proof
        .as_ref()
        .and_then(|p| p.get("audit_root_hash").and_then(|x| x.as_str()))
    {
        exec_rows.push(vec![Cell::from("Audit root hash"), Cell::from(hash)]);
    }

    let mut finding_rows = vec![vec![
        Cell::from("ID"),
        Cell::from("Severity"),
        Cell::from("Title"),
        Cell::from("Source"),
        Cell::from("Status"),
        Cell::from("KEV"),
        Cell::from("EPSS"),
        Cell::from("Proof"),
        Cell::from("Discovered"),
        Cell::from("Remediation"),
    ]];
    let mut leak_rows = vec![vec![
        Cell::from("ID"),
        Cell::from("Severity"),
        Cell::from("Title"),
        Cell::from("Source"),
        Cell::from("Discovered"),
    ]];
    let mut rem_rows = vec![vec![
        Cell::from("ID"),
        Cell::from("Severity"),
        Cell::from("Title"),
        Cell::from("Remediation"),
        Cell::from("KEV"),
        Cell::from("Proof"),
    ]];
    for f in &pack.findings {
        finding_rows.push(vec![
            Cell::from(format!("VLN-{}", f.id)),
            Cell::from(f.severity.as_str()),
            Cell::from(f.title.as_str()),
            Cell::from(f.source.as_str()),
            Cell::from(f.status.as_str()),
            Cell::from(if f.kev_listed { "yes" } else { "no" }),
            Cell::from(f.epss_score as f64),
            Cell::from(if f.has_proof { "yes" } else { "no" }),
            Cell::from(f.discovered_at.as_str()),
            Cell::from(f.remediation.as_str()),
        ]);
        if is_leak_source(&f.source) {
            leak_rows.push(vec![
                Cell::from(format!("VLN-{}", f.id)),
                Cell::from(f.severity.as_str()),
                Cell::from(f.title.as_str()),
                Cell::from(f.source.as_str()),
                Cell::from(f.discovered_at.as_str()),
            ]);
        }
        rem_rows.push(vec![
            Cell::from(format!("VLN-{}", f.id)),
            Cell::from(f.severity.as_str()),
            Cell::from(f.title.as_str()),
            Cell::from(if f.remediation.is_empty() {
                "See engine default remediation in Command Center"
            } else {
                f.remediation.as_str()
            }),
            Cell::from(if f.kev_listed { "yes" } else { "no" }),
            Cell::from(if f.has_proof { "yes" } else { "no" }),
        ]);
    }

    let mut path_rows = vec![vec![
        Cell::from("Hops"),
        Cell::from("Risk"),
        Cell::from("Score"),
        Cell::from("ALE USD"),
        Cell::from("KEV hops"),
        Cell::from("Path"),
    ]];
    if let Some(ap) = &pack.attack_paths {
        if let Some(paths) = ap.get("paths").and_then(|x| x.as_array()) {
            for p in paths.iter().take(40) {
                let hops = p.get("hops").and_then(|x| x.as_u64()).unwrap_or(0) as i64;
                let risk = p.get("risk").and_then(|x| x.as_f64()).unwrap_or(0.0);
                let score = p.get("path_score").and_then(|x| x.as_u64()).unwrap_or(0) as i64;
                let ale = p.get("ale_usd").and_then(|x| x.as_i64()).unwrap_or(0);
                let kev = p.get("kev_hops").and_then(|x| x.as_u64()).unwrap_or(0) as i64;
                let chain = p
                    .get("steps")
                    .and_then(|x| x.as_array())
                    .map(|steps| {
                        steps
                            .iter()
                            .filter_map(|s| s.get("label").and_then(|x| x.as_str()))
                            .collect::<Vec<_>>()
                            .join(" → ")
                    })
                    .unwrap_or_default();
                path_rows.push(vec![
                    Cell::from(hops),
                    Cell::from(risk),
                    Cell::from(score),
                    Cell::from(ale),
                    Cell::from(kev),
                    Cell::from(chain),
                ]);
            }
        }
    }

    let mut fin_rows = vec![vec![Cell::from("Field"), Cell::from("Value")]];
    if let Some(fin) = &pack.financial {
        for key in [
            "ale_annualised_usd",
            "sle_worst_usd",
            "crown_jewel_value_usd",
            "total_asset_value_usd",
            "currency",
            "delay_cost_usd_per_day",
        ] {
            let val = fin
                .get(key)
                .map(|x| x.to_string().trim_matches('"').to_string())
                .unwrap_or_else(|| "—".into());
            fin_rows.push(vec![Cell::from(key), Cell::from(val)]);
        }
    } else {
        fin_rows.push(vec![
            Cell::from("snapshot"),
            Cell::from("none — compute via GET /api/financial-risk/:id?recompute=1"),
        ]);
    }

    let mut evidence_rows = vec![
        vec![Cell::from("Kind"), Cell::from("Value")],
        vec![Cell::from("pack_sha256"), Cell::from(pack.pack_sha256.as_str())],
        vec![
            Cell::from("audit_root_hash"),
            Cell::from(
                pack.crypto_proof
                    .as_ref()
                    .and_then(|p| p.get("audit_root_hash").and_then(|x| x.as_str()))
                    .unwrap_or(""),
            ),
        ],
        vec![
            Cell::from("verification_url"),
            Cell::from(
                pack.crypto_proof
                    .as_ref()
                    .and_then(|p| p.get("verification_url").and_then(|x| x.as_str()))
                    .unwrap_or(""),
            ),
        ],
        vec![Cell::from("pdf"), Cell::from(format!("/api/clients/{}/report/pdf", pack.client_id))],
        vec![Cell::from("xlsx"), Cell::from(format!("/api/clients/{}/report/xlsx", pack.client_id))],
    ];
    evidence_rows.push(vec![
        Cell::from("sources"),
        Cell::from("live DB findings + optional FAIR snapshot + optional attack-path snapshot + crypto proof"),
    ]);

    build_xlsx(&[
        Sheet::new("Executive", exec_rows),
        Sheet::new("Findings", finding_rows),
        Sheet::new("LeakIntel", leak_rows),
        Sheet::new("AttackPaths", path_rows),
        Sheet::new("Financial", fin_rows),
        Sheet::new("Remediation", rem_rows),
        Sheet::new("Evidence", evidence_rows),
    ])
}

pub async fn run_dominion_fusion_result(target: &str) -> crate::engine_result::EngineResult {
    if target.trim().is_empty() {
        return crate::engine_result::EngineResult::error("target required");
    }
    let report = crate::public_leak_osint::collect_public_leak_osint(target).await;
    let mut findings = report.findings;
    for f in findings.iter_mut() {
        if let Some(obj) = f.as_object_mut() {
            obj.insert("type".into(), json!("dominion_fusion"));
        }
    }
    let summary = crate::engine_probes::finding(
        "dominion_fusion",
        "Dominion public-intel fusion completed",
        "info",
        "T1597",
        &format!(
            "Live sources attempted={} live={}. Findings from crt.sh / urlscan / URLHaus / ThreatFox / IntelX / OTX are evidence-backed HTTP responses. This engine does not access Tor hidden services.",
            report.sources_attempted.join(","),
            if report.sources_live.is_empty() {
                "none-yet".into()
            } else {
                report.sources_live.join(",")
            }
        ),
        target,
    );
    findings.insert(0, summary);
    crate::engine_result::EngineResult::ok(
        findings.clone(),
        format!("dominion_fusion: {}", findings.len()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: i64, sev: &str, src: &str, proof: &str, kev: bool) -> DominionFindingInput {
        DominionFindingInput {
            id,
            title: format!("finding-{id}"),
            severity: sev.into(),
            source: src.into(),
            status: "OPEN".into(),
            discovered_at: "2026-09-11".into(),
            description: r#"{"remediation":"rotate keys"}"#.into(),
            poc_exploit: proof.into(),
            proof: String::new(),
            kev_listed: kev,
            epss_score: 0.4,
        }
    }

    #[test]
    fn empty_ledger_is_not_a_clean_bill() {
        let p = build_pack(7, "Acme", vec![], None, None, None);
        assert!(p.grade.contains("NO LEDGER"));
        assert!(p.live);
        assert_eq!(p.kpis.total, 0);
        assert!(!p.pack_sha256.is_empty());
    }

    #[test]
    fn kev_and_critical_force_p0() {
        let p = build_pack(
            1,
            "Acme",
            vec![row(1, "critical", "jwt_attack", "curl -I", true)],
            None,
            None,
            None,
        );
        assert!(p.grade.starts_with("P0"));
        assert_eq!(p.kpis.critical, 1);
        assert_eq!(p.kpis.kev, 1);
        assert_eq!(p.kpis.with_proof, 1);
    }

    #[test]
    fn leak_source_counts_and_xlsx_has_sheets() {
        let p = build_pack(
            2,
            "Beta",
            vec![row(9, "high", "darkweb_intel", "", false)],
            Some(json!({"ale_annualised_usd": 120000, "sle_worst_usd": 50000, "crown_jewel_value_usd": 800000})),
            None,
            Some(json!({"audit_root_hash": "abc"})),
        );
        assert!(p.grade.starts_with("P1"));
        assert_eq!(p.kpis.leak, 1);
        let xlsx = pack_to_xlsx(&p).expect("xlsx");
        assert!(xlsx.starts_with(b"PK"));
        let s = String::from_utf8_lossy(&xlsx);
        assert!(s.contains("Executive"));
        assert!(s.contains("LeakIntel"));
        assert!(s.contains("Financial"));
        assert!(s.contains("abc"));
    }
}
