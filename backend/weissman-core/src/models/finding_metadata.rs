//! Title, severity label, and DB description derived from engine JSON payloads (orchestrator / workers).

use serde_json::{Map, Value};

/// Dashboard title and severity string from a finding JSON object.
pub fn finding_title_and_severity(obj: &Map<String, Value>) -> (String, String) {
    let title = obj
        .get("title")
        .and_then(Value::as_str)
        .map(String::from)
        .or_else(|| {
            obj.get("cve_id")
                .and_then(Value::as_str)
                .map(|c| c.trim().to_string())
                .filter(|c| !c.is_empty())
        })
        .or_else(|| {
            if obj.get("type").and_then(Value::as_str) == Some("supply_chain") {
                let pkg = obj.get("package").and_then(Value::as_str).unwrap_or("?");
                let eco = obj
                    .get("ecosystem")
                    .and_then(Value::as_str)
                    .unwrap_or("?");
                let vc = obj.get("vuln_count").and_then(Value::as_u64).unwrap_or(0);
                let ids = obj
                    .get("osv_ids")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .take(3)
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .filter(|s| !s.is_empty());
                Some(if vc == 0 {
                    format!("Supply chain ({eco}): {pkg} — no OSV advisories")
                } else if let Some(ref i) = ids {
                    format!("Supply chain ({eco}): {pkg} — {vc} OSV ({i})")
                } else {
                    format!("Supply chain ({eco}): {pkg} — {vc} OSV advisories")
                })
            } else {
                None
            }
        })
        .or_else(|| {
            obj.get("url")
                .and_then(Value::as_str)
                .map(|u| {
                    let m = obj
                        .get("method")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let p = obj.get("path").and_then(Value::as_str).unwrap_or("");
                    if !m.is_empty() && !p.is_empty() {
                        format!("{m} {p} → {u}")
                    } else if !p.is_empty() {
                        format!("{p} ({u})")
                    } else {
                        u.to_string()
                    }
                })
        })
        .or_else(|| obj.get("value").and_then(Value::as_str).map(String::from))
        .or_else(|| obj.get("path").and_then(Value::as_str).map(String::from))
        .or_else(|| {
            obj.get("package")
                .and_then(Value::as_str)
                .map(|p| format!("package {}", p))
        })
        .or_else(|| {
            obj.get("type")
                .and_then(Value::as_str)
                .map(|t| format!("{} finding", t))
        })
        .or_else(|| {
            obj.get("message")
                .and_then(Value::as_str)
                .map(|m| m.chars().take(200).collect::<String>())
        })
        .unwrap_or_else(|| "Finding".to_string());
    let severity = obj
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("info")
        .to_string();
    (title, severity)
}

/// Build `vulnerabilities.description` text: timing / AI redteam / CVE / footprint / fallback JSON.
pub fn finding_description(obj: &Map<String, Value>) -> String {
    if obj.get("delta_us").is_some() || obj.get("z_score").is_some() {
        let delta = obj.get("delta_us").and_then(Value::as_f64).unwrap_or(0.0);
        let z = obj.get("z_score").and_then(Value::as_f64).unwrap_or(0.0);
        let payload = obj
            .get("payload_preview")
            .and_then(Value::as_str)
            .unwrap_or("");
        let conf = obj
            .get("confidence_pct")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        format!(
            "delta_us={:.0} z_score={:.2} confidence={:.1}% payload_preview={}",
            delta, z, conf, payload
        )
    } else if obj.get("injection_vector").is_some() {
        let inj = obj
            .get("injection_vector")
            .and_then(Value::as_str)
            .unwrap_or("");
        let judge = obj
            .get("judge_explanation")
            .and_then(Value::as_str)
            .unwrap_or("");
        format!(
            "injection_vector={} | judge={}",
            inj.chars().take(300).collect::<String>(),
            judge.chars().take(400).collect::<String>()
        )
    } else if obj.get("cve_id").is_some() {
        let cve = obj.get("cve_id").and_then(Value::as_str).unwrap_or("");
        let url = obj.get("target_url").and_then(Value::as_str).unwrap_or("");
        let path = obj.get("probe_path").and_then(Value::as_str).unwrap_or("");
        format!("cve_id={} target_url={} probe_path={}", cve, url, path)
    } else if obj.get("footprint").is_some() {
        let footprint = obj.get("footprint").and_then(Value::as_str).unwrap_or("");
        let verified = obj
            .get("verified")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        format!(
            "footprint={} verified={} weaponization_status=SAFE (Proof of Exploitability Only)",
            footprint, verified
        )
    } else if obj.get("type").and_then(Value::as_str) == Some("supply_chain") {
        let pkg = obj.get("package").and_then(Value::as_str).unwrap_or("");
        let ver = obj.get("version").and_then(Value::as_str).unwrap_or("");
        let eco = obj.get("ecosystem").and_then(Value::as_str).unwrap_or("");
        let vc = obj.get("vuln_count").and_then(Value::as_u64).unwrap_or(0);
        let ids = obj
            .get("osv_ids")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        let summ = obj
            .get("osv_summaries")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .take(5)
                    .collect::<Vec<_>>()
                    .join(" | ")
            })
            .unwrap_or_default();
        let poc = obj
            .get("poc_exploit")
            .and_then(Value::as_str)
            .unwrap_or("")
            .chars()
            .take(4000)
            .collect::<String>();
        format!(
            "ecosystem={eco} package={pkg} version={ver} osv_vuln_count={vc} osv_ids=[{}] summaries=[{}] reproducibility_curl_block={}",
            ids.chars().take(2000).collect::<String>(),
            summ.chars().take(2000).collect::<String>(),
            poc
        )
    } else if obj.get("url").is_some() || obj.get("request_body").is_some() {
        let url = obj.get("url").and_then(Value::as_str).unwrap_or("");
        let method = obj.get("method").and_then(Value::as_str).unwrap_or("");
        let path = obj.get("path").and_then(Value::as_str).unwrap_or("");
        let body = obj
            .get("request_body")
            .and_then(Value::as_str)
            .unwrap_or("")
            .chars()
            .take(800)
            .collect::<String>();
        let status = obj
            .get("server_status")
            .or_else(|| obj.get("response_status"))
            .and_then(|v| {
                if let Some(u) = v.as_u64() {
                    Some(u.to_string())
                } else {
                    v.as_str().map(String::from)
                }
            })
            .unwrap_or_default();
        let prev = obj
            .get("payload_preview")
            .and_then(Value::as_str)
            .unwrap_or("")
            .chars()
            .take(400)
            .collect::<String>();
        format!(
            "method={method} path={path} url={url} http_status={status} payload_preview={} request_body_excerpt={body}",
            prev
        )
    } else {
        serde_json::to_string(&Value::Object(obj.clone()))
            .unwrap_or_default()
            .chars()
            .take(12000)
            .collect()
    }
}
