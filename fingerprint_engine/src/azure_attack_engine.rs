//! Azure Attack Engine — probes for Azure metadata, SAS tokens, storage, and Azure AD tenant info.
//! MITRE: T1552 (Unsecured Credentials).

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

fn extract_domain(target: &str) -> String {
    let t = target.trim();
    let without_scheme = if let Some(s) = t.strip_prefix("https://") {
        s
    } else if let Some(s) = t.strip_prefix("http://") {
        s
    } else {
        t
    };
    without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .split(':')
        .next()
        .unwrap_or(without_scheme)
        .to_string()
}

const AZURE_WEB_PATHS: &[&str] = &[
    "/.well-known/",
    "/azure-appservice-site/",
    "/azure/",
    "/.azure/",
    "/azure-credentials.json",
    "/.env.azure",
    "/appsettings.json",
    "/web.config",
];

const SAS_TOKEN_INDICATORS: &[&str] = &[
    "sv=",
    "sig=",
    "se=",
    "sp=",
    "spr=",
    "sr=b",
    "blob.core.windows.net",
    "AccountKey=",
    "DefaultEndpointsProtocol=",
    "SharedAccessSignature",
];

pub async fn run_azure_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }

    let client = build_client().await;
    let base = normalize_target(target);
    let domain = extract_domain(&base);
    let mut findings = Vec::new();

    // Check Azure IMDS metadata endpoint
    let imds_url = "http://169.254.169.254/metadata/instance?api-version=2021-02-01";
    if let Ok(resp) = client
        .get(imds_url)
        .header("Metadata", "true")
        .timeout(Duration::from_secs(3))
        .send()
        .await
    {
        if resp.status().as_u16() == 200 {
            let body = resp.text().await.unwrap_or_default();
            findings.push(json!({
                "type": "azure_attack",
                "title": "Azure Instance Metadata Service (IMDS) Accessible",
                "severity": "critical",
                "mitre_attack": "T1552",
                "description": format!(
                    "Azure IMDS at {} is accessible. This exposes subscription IDs, resource groups, VM metadata, and potentially managed identity tokens. Preview: {}",
                    imds_url,
                    &body[..body.len().min(300)]
                )
            }));
        }
    }

    // Check for Azure AD tenant info
    let tenant_url = format!(
        "https://login.microsoftonline.com/{}/.well-known/openid-configuration",
        domain
    );
    if let Ok(resp) = client.get(&tenant_url).send().await {
        let status = resp.status().as_u16();
        if status == 200 {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("tenant_id") || body.contains("authorization_endpoint") {
                findings.push(json!({
                    "type": "azure_attack",
                    "title": "Azure AD Tenant Discoverable",
                    "severity": "medium",
                    "mitre_attack": "T1552",
                    "description": format!(
                        "Azure AD tenant for domain '{}' is discoverable via {}. Tenant information can be used for phishing and credential attacks.",
                        domain, tenant_url
                    )
                }));
            }
        }
    }

    // Check web paths for Azure-specific files and SAS tokens
    for path in AZURE_WEB_PATHS {
        let url = format!("{}{}", base, path);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            if status == 200 {
                let body = resp.text().await.unwrap_or_default();
                let has_sas = SAS_TOKEN_INDICATORS.iter().any(|ind| body.contains(ind));

                if has_sas {
                    findings.push(json!({
                        "type": "azure_attack",
                        "title": format!("Azure SAS Token / Storage Credentials Exposed at {}", path),
                        "severity": "critical",
                        "mitre_attack": "T1552",
                        "description": format!(
                            "File at {} (HTTP {}) contains Azure SAS token or storage connection string indicators. Immediate rotation required.",
                            url, status
                        )
                    }));
                } else {
                    findings.push(json!({
                        "type": "azure_attack",
                        "title": format!("Azure Configuration File Accessible: {}", path),
                        "severity": "medium",
                        "mitre_attack": "T1552",
                        "description": format!(
                            "Azure-related configuration path {} is publicly accessible (HTTP {}). Review for sensitive data exposure.",
                            url, status
                        )
                    }));
                }
            }
        }
    }

    EngineResult::ok(findings.clone(), format!("Azure Attack: {} findings", findings.len()))
}

pub async fn run_azure_attack(target: &str) {
    print_result(run_azure_attack_result(target).await);
}
