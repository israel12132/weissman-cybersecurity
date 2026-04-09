//! Zero-Day Prediction Engine — uses NVD CVE history and component analysis to predict high-risk components.

use crate::engine_result::{print_result, EngineResult};
use serde_json::json;
use std::time::Duration;

async fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn normalize_target(target: &str) -> String {
    let t = target.trim();
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t)
    }
}

/// Components historically associated with high CVE frequency and zero-day discovery.
/// Format: (component, historical_cve_count_estimate, risk_level, mitre_pattern)
const HIGH_RISK_COMPONENTS: &[(&str, u32, &str, &str)] = &[
    ("openssl", 85, "critical", "Buffer overflow, format string, heap UAF vulnerabilities historically common"),
    ("log4j", 12, "critical", "Log4Shell class of vulnerabilities; JNDI injection surface"),
    ("apache", 320, "high", "Large attack surface; mod_* modules frequently have CVEs"),
    ("nginx", 45, "medium", "Memory corruption and HTTP request handling vulnerabilities"),
    ("wordpress", 890, "high", "Plugin ecosystem drives constant CVE stream; core has privilege escalation history"),
    ("php", 430, "high", "Type confusion, deserialization, file inclusion consistently exploited"),
    ("spring", 38, "high", "Spring4Shell class; SpEL injection; deserialization via Java gadgets"),
    ("struts", 52, "critical", "Repeated RCE via OGNL injection; Equifax breach vector"),
    ("jenkins", 67, "high", "Groovy script RCE; Groovy sandbox escapes; SSRF via plugins"),
    ("gitlab", 89, "high", "Path traversal, SSRF, RCE; frequent critical advisories"),
    ("confluence", 41, "critical", "Repeated authentication bypass and RCE CVEs (CVE-2022-26134 class)"),
    ("jira", 56, "high", "SSRF, template injection, auth bypass vulnerabilities"),
    ("redis", 28, "high", "Unauthenticated access RCE via config manipulation"),
    ("elasticsearch", 22, "high", "Unauth access enabling data exposure; Groovy scripting RCE history"),
    ("iis", 98, "high", "HTTP.sys vulnerabilities; kernel pool overflow history"),
    ("exchange", 67, "critical", "ProxyLogon, ProxyShell, ProxyNotShell class; remote code execution chain"),
    ("tomcat", 44, "high", "AJP ghostcat, partial PUT deserialization; common Java app server"),
    ("drupal", 78, "high", "Drupalgeddon class; RCE via form API; active exploitation history"),
    ("joomla", 65, "high", "SQL injection and RCE; popular CMS with large plugin attack surface"),
    ("jquery", 15, "medium", "XSS via prototype pollution; DOM-based injection"),
    ("vmware", 145, "critical", "vCenter, ESXi, Workspace ONE consistently targeted; nation-state exploitation"),
    ("citrix", 38, "critical", "Netscaler/ADC directory traversal; session fixation; RCE history"),
    ("fortinet", 42, "critical", "FortiOS SSL-VPN path traversal; heap overflow RCE"),
    ("pulse", 28, "critical", "Pulse Secure VPN pre-auth RCE; actively exploited by APTs"),
];

pub async fn run_zero_day_prediction_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_target(target);
    let client = build_client().await;
    let mut findings: Vec<serde_json::Value> = Vec::new();

    // Step 1: Fingerprint the target's technology stack
    let mut detected_components: Vec<String> = Vec::new();

    if let Ok(resp) = client.get(&base).send().await {
        let headers = resp.headers().clone();
        let server = headers
            .get("server")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();
        let powered_by = headers
            .get("x-powered-by")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();
        let body = resp.text().await.unwrap_or_default().to_lowercase();

        let all_text = format!("{} {} {}", server, powered_by, &body[..body.len().min(5000)]);

        // Detect components from server headers and page content
        let detectable: &[(&str, &[&str])] = &[
            ("openssl", &["openssl"]),
            ("apache", &["apache", "httpd"]),
            ("nginx", &["nginx"]),
            ("iis", &["iis", "microsoft-iis"]),
            ("wordpress", &["wordpress", "wp-content", "wp-includes"]),
            ("drupal", &["drupal", "sites/default", "drupal.org"]),
            ("joomla", &["joomla", "mootools-core"]),
            ("php", &["php/", "x-powered-by: php"]),
            ("spring", &["spring", "whitelabel error page"]),
            ("struts", &["struts", "org.apache.struts"]),
            ("jenkins", &["jenkins", "hudson"]),
            ("confluence", &["confluence", "atlassian"]),
            ("jira", &["jira", "atlassian.net"]),
            ("gitlab", &["gitlab"]),
            ("jquery", &["jquery"]),
            ("redis", &["redis"]),
            ("tomcat", &["tomcat", "coyote"]),
            ("exchange", &["exchange", "owa", "microsoft exchange"]),
            ("citrix", &["citrix", "netscaler"]),
        ];

        for (component, patterns) in detectable {
            if patterns.iter().any(|p| all_text.contains(p)) {
                detected_components.push(component.to_string());
            }
        }
    }

    // Step 2: Cross-reference with high-risk component database
    for component in &detected_components {
        if let Some(&(name, cve_count, risk, pattern)) = HIGH_RISK_COMPONENTS
            .iter()
            .find(|(n, _, _, _)| n == component)
        {
            findings.push(json!({
                "type": "zero_day_prediction",
                "title": format!("High zero-day risk component detected: {} ({} historical CVEs)", name, cve_count),
                "severity": risk,
                "mitre_attack": "T1212",
                "description": format!(
                    "Component '{}' detected on target with {} historical CVEs. Pattern: {}. \
                    Components with high historical CVE rates are statistically more likely to have \
                    undisclosed vulnerabilities. Prioritize patching and consider virtual patching \
                    via WAF rules. Monitor NVD/VulnDB for new advisories.",
                    name, cve_count, pattern
                ),
                "value": base,
                "component": name,
                "historical_cve_count": cve_count,
                "risk_level": risk
            }));
        }
    }

    // Step 3: Query NVD for recent CVEs for detected components
    for component in detected_components.iter().take(3) {
        let nvd_url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=3",
            component
        );
        if let Ok(resp) = client.get(&nvd_url).send().await {
            if resp.status().as_u16() == 200 {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    let total = data.get("totalResults").and_then(|t| t.as_u64()).unwrap_or(0);
                    if total > 0 {
                        let recent_id = data
                            .get("vulnerabilities")
                            .and_then(|v| v.as_array())
                            .and_then(|arr| arr.first())
                            .and_then(|v| v.get("cve"))
                            .and_then(|c| c.get("id"))
                            .and_then(|id| id.as_str())
                            .unwrap_or("unknown");

                        findings.push(json!({
                            "type": "zero_day_prediction",
                            "title": format!("NVD: {} total CVEs for '{}', most recent: {}", total, component, recent_id),
                            "severity": "info",
                            "mitre_attack": "T1212",
                            "description": format!(
                                "NVD database contains {} CVEs for component '{}'. Most recent: {}. \
                                High CVE velocity indicates active research and exploitation interest — \
                                predictive indicator of near-term zero-day disclosure.",
                                total, component, recent_id
                            ),
                            "value": base,
                            "component": component,
                            "nvd_total_cves": total,
                            "most_recent_cve": recent_id
                        }));
                    }
                }
            }
        }
    }

    if findings.is_empty() {
        findings.push(json!({
            "type": "zero_day_prediction",
            "title": format!("No high-risk components detected on {}", base),
            "severity": "info",
            "mitre_attack": "T1212",
            "description": "Zero-day prediction scan found no known high-risk components in the fingerprinted technology stack.",
            "value": base
        }));
    }

    EngineResult::ok(
        findings.clone(),
        format!("ZeroDayPrediction: {} risk findings for {} detected components", findings.len(), detected_components.len()),
    )
}

pub async fn run_zero_day_prediction(target: &str) {
    print_result(run_zero_day_prediction_result(target).await);
}
