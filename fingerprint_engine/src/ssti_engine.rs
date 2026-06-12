//! SSTI Engine — template injection probing with reflection-aware arithmetic detection.
//! MITRE: T1059 (Command and Scripting Interpreter).

use crate::engine_probes::{
    empty_ok, finding_with_probe_depth, http_client, http_get, normalize_url,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};
use std::time::Duration;

const SSTI_PROBE_DEPTH: &str = "ssti_template_surface";

fn ssti_finding(
    title: &str,
    severity: &str,
    description: &str,
    target: &str,
    extra: Value,
) -> Value {
    let mut f = finding_with_probe_depth(
        "ssti",
        title,
        severity,
        "T1059",
        description,
        target,
        SSTI_PROBE_DEPTH,
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

const SSTI_PAYLOADS: &[(&str, &str, &str)] = &[
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("${7*7}", "49", "Freemarker/Spring EL"),
    ("<%= 7*7 %>", "49", "ERB/EJS"),
    ("#{7*7}", "49", "Thymeleaf"),
    ("{{7*'7'}}", "7777777", "Jinja2"),
];

const PROBE_PARAMS: &[&str] = &[
    "q", "search", "query", "name", "input", "msg", "message", "text", "value", "template", "page",
    "id", "title", "content", "data",
];

const PROBE_PATHS: &[&str] = &[
    "/",
    "/search",
    "/index",
    "/home",
    "/api/render",
    "/template",
    "/render",
    "/preview",
    "/api/preview",
];

fn ssti_confirmed(body: &str, payload: &str, expected: &str) -> bool {
    body.contains(expected) && !body.contains(payload)
}

async fn http_post_form(
    client: &reqwest::Client,
    url: &str,
    form: &str,
) -> Option<crate::engine_probes::HttpProbe> {
    let resp = client
        .post(url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(form.to_string())
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
    let body = resp.text().await.unwrap_or_default();
    let body = if body.len() > 65_536 {
        body[..65_536].to_string()
    } else {
        body
    };
    Some(crate::engine_probes::HttpProbe {
        status,
        headers,
        body,
        final_url,
    })
}

pub async fn run_ssti_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();

    'outer: for path in PROBE_PATHS {
        let url_base = format!("{}{}", base.trim_end_matches('/'), path);
        for param in PROBE_PARAMS {
            for (payload, expected, engine_type) in SSTI_PAYLOADS {
                let encoded = urlencoding::encode(payload);
                let probe_url = format!("{}?{}={}", url_base, param, encoded);
                if let Some(p) = http_get(&client, &probe_url).await {
                    if (p.status == 200 || p.status == 201)
                        && ssti_confirmed(&p.body, payload, expected)
                    {
                        findings.push(ssti_finding(
                            &format!("SSTI confirmed ({})", engine_type),
                            "critical",
                            &format!(
                                "Parameter '{}' on {} evaluated '{}' → '{}' (HTTP {}).",
                                param, p.final_url, payload, expected, p.status
                            ),
                            target,
                            json!({ "parameter": param, "payload": payload, "engine": engine_type }),
                        ));
                        break 'outer;
                    }
                }
            }
        }
    }

    if findings.is_empty() {
        for path in PROBE_PATHS {
            let url = format!("{}{}", base.trim_end_matches('/'), path);
            for (payload, expected, engine_type) in SSTI_PAYLOADS {
                for field in PROBE_PARAMS.iter().take(6) {
                    let form = format!("{}={}", field, urlencoding::encode(payload));
                    if let Some(p) = http_post_form(&client, &url, &form).await {
                        if ssti_confirmed(&p.body, payload, expected) {
                            findings.push(ssti_finding(
                                &format!("SSTI confirmed via POST ({})", engine_type),
                                "critical",
                                &format!(
                                    "POST field '{}' on {} evaluated '{}' → '{}'.",
                                    field, p.final_url, payload, expected
                                ),
                                target,
                                json!({ "field": field, "payload": payload }),
                            ));
                            break;
                        }
                    }
                }
                if !findings.is_empty() {
                    break;
                }
            }
            if !findings.is_empty() {
                break;
            }
        }
    }

    if findings.is_empty() {
        empty_ok("ssti", target)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("ssti: {} live finding(s)", n))
    }
}

pub async fn run_ssti(target: &str) {
    print_result(run_ssti_result(target).await);
}
