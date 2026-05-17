//! Adversarial ML Engine — probes ML model endpoints for adversarial inputs and architecture leakage.
//! MITRE: T1059 (Command and Scripting Interpreter).

use crate::engine_result::{print_result, EngineResult};
use serde_json::json;
use std::time::Duration;

async fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn normalize_target(target: &str) -> String {
    let t = target.trim().trim_end_matches('/');
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t)
    }
}

const ML_PATHS: &[&str] = &[
    "/predict",
    "/inference",
    "/api/predict",
    "/model/predict",
    "/score",
    "/classify",
    "/api/v1/predict",
    "/api/inference",
    "/ml/predict",
    "/v1/predict",
];

const ADVERSARIAL_PAYLOADS: &[(&str, &str)] = &[
    ("malformed_json", "{not valid json at all ][}"),
    ("empty_input", r#"{"input": null}"#),
    ("large_payload", r#"{"input": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#),
    ("type_confusion", r#"{"input": {"nested": {"deeply": {"key": [1, 2, 3, null, true, "string"]}}}}"#),
    ("negative_values", r#"{"input": [-999999999, -1.7976931348623157e+308, 0, 1.7976931348623157e+308]}"#),
    ("unicode_fuzzing", r#"{"input": "\u0000\u0001\u0002\uFFFF\uD800\uDFFF"}"#),
];

const ARCH_LEAK_INDICATORS: &[&str] = &[
    "tensorflow",
    "pytorch",
    "keras",
    "sklearn",
    "scikit",
    "xgboost",
    "lightgbm",
    "model",
    "layer",
    "neuron",
    "gradient",
    "traceback",
    "exception",
    "stack trace",
    "at line",
    "error in",
    "valueerror",
    "typeerror",
    "runtimeerror",
];

pub async fn run_adversarial_ml_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }

    let client = build_client().await;
    let base = normalize_target(target);
    let mut findings = Vec::new();

    for path in ML_PATHS {
        let url = format!("{}{}", base, path);

        let probe = client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await;

        let endpoint_exists = match &probe {
            Ok(r) => {
                let s = r.status().as_u16();
                s == 200 || s == 405 || s == 401 || s == 403 || s == 422 || s == 400
            }
            Err(_) => false,
        };

        if !endpoint_exists {
            continue;
        }

        findings.push(json!({
            "type": "adversarial_ml",
            "title": format!("ML Model Endpoint Discovered: {}", path),
            "severity": "medium",
            "mitre_attack": "T1059",
            "description": format!(
                "A potential ML model endpoint was found at {}. Testing for adversarial input vulnerabilities.",
                url
            )
        }));

        for (payload_name, payload_body) in ADVERSARIAL_PAYLOADS {
            if let Ok(resp) = client
                .post(&url)
                .header("Content-Type", "application/json")
                .body(*payload_body)
                .send()
                .await
            {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default().to_lowercase();

                let leaks_arch = ARCH_LEAK_INDICATORS.iter().any(|ind| body.contains(ind));

                if leaks_arch && (status == 400 || status == 422 || status == 500) {
                    findings.push(json!({
                        "type": "adversarial_ml",
                        "title": format!("ML Model Architecture Leakage via {}", payload_name),
                        "severity": "high",
                        "mitre_attack": "T1059",
                        "description": format!(
                            "The ML endpoint at {} returned error details (HTTP {}) when sent '{}' payload, leaking potential model architecture or framework information.",
                            url, status, payload_name
                        )
                    }));
                } else if status == 500 {
                    findings.push(json!({
                        "type": "adversarial_ml",
                        "title": format!("ML Endpoint Server Error via {}", payload_name),
                        "severity": "medium",
                        "mitre_attack": "T1059",
                        "description": format!(
                            "The ML endpoint at {} returned HTTP {} when sent '{}' adversarial payload. The model may not handle edge cases robustly.",
                            url, status, payload_name
                        )
                    }));
                }
            }
        }
    }

    EngineResult::ok(findings.clone(), format!("Adversarial ML: {} findings", findings.len()))
}

pub async fn run_adversarial_ml(target: &str) {
    print_result(run_adversarial_ml_result(target).await);
}
