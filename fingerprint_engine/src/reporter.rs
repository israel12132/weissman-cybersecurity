//! Local bug bounty report generation. LLM-assisted triage (vLLM) with static fallback;
//! HackerOne/Bugcrowd-style Markdown to `reports/`, then optional NOTIFY_URL webhook (retries intact).

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::json;
use weissman_engines::openai_chat::{self, DEFAULT_LLM_BASE_URL};

const SYSTEM_TRIAGE: &str = r#"You are a principal application security analyst writing an internal bug bounty triage.

Output ONLY a single JSON object with exactly these three string fields (no markdown fences, no commentary):
- "severity": one of Low, Medium, High, Critical (title case preferred).
- "dynamic_impact": one focused paragraph on business and technical risk of this exact finding (specific to the payload and baseline delta).
- "remediation": numbered or short step-by-step remediation tailored to this anomaly class.

Be precise and professional; do not invent CVEs or claim exploitation without evidence from the supplied data."#;

/// LLM-produced sections injected into the Markdown template.
#[derive(Clone, Debug)]
pub struct BugReportTriage {
    pub severity: String,
    pub dynamic_impact: String,
    pub remediation: String,
}

#[derive(Deserialize)]
struct LlmTriageRaw {
    severity: String,
    dynamic_impact: String,
    remediation: String,
}

fn strip_code_fence(s: &str) -> String {
    let t = s.trim();
    if let Some(rest) = t.strip_prefix("```") {
        let mut lines = rest.lines();
        let first = lines.next().unwrap_or("");
        let body: String = if first.trim_start().starts_with('{') {
            format!("{}\n{}", first, lines.collect::<Vec<_>>().join("\n"))
        } else {
            lines.collect::<Vec<_>>().join("\n")
        };
        let body = body.trim();
        if let Some(idx) = body.rfind("```") {
            body[..idx].trim().to_string()
        } else {
            body.to_string()
        }
    } else {
        t.to_string()
    }
}

fn parse_triage_json(text: &str) -> Option<BugReportTriage> {
    let cleaned = strip_code_fence(text);
    let v: LlmTriageRaw = serde_json::from_str(&cleaned).ok()?;
    let sev = v.severity.trim().to_string();
    let imp = v.dynamic_impact.trim().to_string();
    let rem = v.remediation.trim().to_string();
    if sev.is_empty() || imp.is_empty() || rem.is_empty() {
        return None;
    }
    Some(BugReportTriage {
        severity: sev,
        dynamic_impact: imp,
        remediation: rem,
    })
}

fn severity_badge_line(severity: &str) -> String {
    let s = severity.trim().to_lowercase();
    match s.as_str() {
        "critical" => "🔴 **CRITICAL** *(automated LLM triage)*".to_string(),
        "high" => "🟠 **HIGH** *(automated LLM triage)*".to_string(),
        "medium" => "🟡 **MEDIUM** *(automated LLM triage)*".to_string(),
        "low" => "🟢 **LOW** *(automated LLM triage)*".to_string(),
        _ => format!(
            "⚪ **{}** *(automated LLM triage)*",
            severity.trim().to_uppercase()
        ),
    }
}

fn report_llm_timeout_secs() -> u64 {
    std::env::var("WEISSMAN_REPORT_LLM_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(45)
        .clamp(5, 180)
}

fn report_llm_max_tokens() -> u32 {
    std::env::var("WEISSMAN_REPORT_LLM_MAX_TOKENS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1024)
        .clamp(256, 4096)
}

fn report_llm_disabled() -> bool {
    std::env::var("WEISSMAN_REPORT_LLM_DISABLED")
        .ok()
        .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn truncate_for_llm(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}… [truncated {} chars]", &s[..max], s.len() - max)
    }
}

/// Async LLM triage; returns `None` on timeout, error, or parse failure (caller uses static template).
async fn fetch_bug_report_triage(
    target_url: &str,
    mutated_payload: &str,
    anomaly_type: &str,
    baseline_vs_anomaly: &str,
) -> Option<BugReportTriage> {
    if report_llm_disabled() {
        return None;
    }

    let base_url = std::env::var("WEISSMAN_LLM_BASE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_LLM_BASE_URL.to_string());
    let base_url = openai_chat::normalize_openai_base_url(&base_url);
    let model = openai_chat::resolve_llm_model("");

    let user = json!({
        "anomaly_type": anomaly_type,
        "target_url": target_url,
        "mutated_payload_excerpt": truncate_for_llm(mutated_payload, 12_000),
        "baseline_vs_anomaly": truncate_for_llm(baseline_vs_anomaly, 8_000),
    })
    .to_string();

    let client = openai_chat::llm_http_client(report_llm_timeout_secs().saturating_add(10));
    let timeout = std::time::Duration::from_secs(report_llm_timeout_secs());

    let fut = openai_chat::chat_completion_text(
        &client,
        &base_url,
        &model,
        Some(SYSTEM_TRIAGE),
        &user,
        0.35,
        report_llm_max_tokens(),
        None,
        "bug_report_triage",
        true,
    );

    let text = match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            tracing::warn!(target: "reporter", error = %e, "bug report LLM triage failed");
            return None;
        }
        Err(_) => {
            tracing::warn!(target: "reporter", "bug report LLM triage timed out");
            return None;
        }
    };

    parse_triage_json(&text)
}

/// Builds the full Markdown report; `triage` augments severity, impact, and remediation when present.
fn build_report_markdown(
    target_url: &str,
    mutated_payload: &str,
    anomaly_type: &str,
    baseline_vs_anomaly: &str,
    triage: Option<&BugReportTriage>,
) -> String {
    let curl_payload_escaped = mutated_payload.replace('\\', "\\\\").replace('"', "\\\"");

    let severity_section = triage
        .map(|t| {
            format!(
                "\n## Severity assessment\n\n{}\n\n---\n\n",
                severity_badge_line(&t.severity)
            )
        })
        .unwrap_or_default();

    let (vuln_desc_body, business_impact_body, remediation_section) = if let Some(t) = triage {
        let desc = format!(
            "During automated API fuzzing, an anomaly was observed. A **local LLM triage** step classified severity and produced a tailored risk narrative (see **Business Impact** below).\n\n- **Target URL:** `{target_url}`\n- **Anomaly Type:** {anomaly_type}\n- **Baseline vs. Anomaly Data:** {baseline_vs_anomaly}\n\nThe mutated payload that triggered the anomaly is reproduced under *Steps to Reproduce*.",
            target_url = target_url,
            anomaly_type = anomaly_type,
            baseline_vs_anomaly = baseline_vs_anomaly,
        );
        let impact = format!(
            "### Context-aware risk analysis\n\n{}\n\n_Validate in staging; LLM severity and narrative are advisory pending human review._",
            t.dynamic_impact
        );
        let rem = format!(
            "\n---\n\n## Remediation\n\n{}\n\n---\n\n",
            t.remediation
        );
        (desc, impact, rem)
    } else {
        let desc = format!(
            "During automated API fuzzing of the target endpoint, the following anomaly was observed. This may indicate a vulnerability such as injection, denial of service, or improper error handling.\n\n- **Target URL:** `{target_url}`\n- **Anomaly Type:** {anomaly_type}\n- **Baseline vs. Anomaly Data:** {baseline_vs_anomaly}\n\nThe mutated payload that triggered the anomaly is provided below. A qualified security engineer should validate whether this represents a exploitable vulnerability and classify severity according to your program policy.",
            target_url = target_url,
            anomaly_type = anomaly_type,
            baseline_vs_anomaly = baseline_vs_anomaly,
        );
        let impact = r#"- **Availability:** Unusual response times or status 500 may indicate denial of service or server instability.
- **Confidentiality / Integrity:** Payloads that trigger different behavior may indicate injection or parsing flaws.
- **Compliance:** Unhandled inputs can violate security standards and audit requirements.

Recommend validating this finding in a staging environment and applying fixes (input validation, timeouts, error handling) before production."#
            .to_string();
        let rem = "\n---\n\n## Remediation\n\nApply defense-in-depth: validate and sanitize inputs, enforce timeouts, review error handling, and re-test after fixes.\n\n---\n\n".to_string();
        (desc, impact, rem)
    };

    format!(
        r#"# Security Vulnerability Report

## Title
**Anomaly Detected During Fuzzing: {anomaly_type}**
{severity_section}---

## Vulnerability Description

{vuln_desc_body}

---

## Steps to Reproduce

1. Send a baseline request to the target to establish normal behavior (status code, response time, content length).
2. Send a request containing the following payload to the same endpoint.

**Proof of Concept (curl):** Uses actual target URL and payload (no placeholders).

```bash
curl -X POST '{target_url}' \
  -H 'Content-Type: application/json' \
  -d "{curl_payload_escaped}"
```

3. Compare the response (status code, latency, response body size) to the baseline. The anomaly observed was: **{anomaly_type}**.

---

## Business Impact

{business_impact_body}
{remediation_section}*Report generated by Weissman-cybersecurity. Timestamp: {timestamp}*
"#,
        anomaly_type = anomaly_type,
        target_url = target_url,
        curl_payload_escaped = curl_payload_escaped,
        timestamp = format_timestamp(),
        severity_section = severity_section,
        vuln_desc_body = vuln_desc_body,
        business_impact_body = business_impact_body,
        remediation_section = remediation_section,
    )
}

fn format_timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| {
            let secs = d.as_secs();
            let millis = d.subsec_millis();
            format!("{}.{:03}", secs, millis)
        })
        .unwrap_or_else(|_| "0".to_string())
}

/// Safe filename: anomaly_<timestamp>.md
fn report_filename() -> String {
    format!("anomaly_{}.md", format_timestamp())
}

async fn notify_webhook(name: &str) {
    if let Ok(notify_url) = std::env::var("NOTIFY_URL") {
        if let Ok(client) = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
        {
            let body = format!("filename={}", urlencoding::encode(name));
            const MAX_ATTEMPTS: u32 = 3;
            const RETRY_DELAY_SECS: u64 = 5;
            for attempt in 0..MAX_ATTEMPTS {
                let res = client
                    .post(&notify_url)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(body.clone())
                    .send()
                    .await;
                let ok = res
                    .as_ref()
                    .map(|r| r.status().is_success())
                    .unwrap_or(false);
                if ok {
                    break;
                }
                if attempt < MAX_ATTEMPTS - 1 {
                    tokio::time::sleep(std::time::Duration::from_secs(RETRY_DELAY_SECS)).await;
                }
            }
        }
    }
}

async fn generate_bug_report_worker(
    target_url: String,
    mutated_payload: String,
    anomaly_type: String,
    baseline_vs_anomaly: String,
) {
    let triage = fetch_bug_report_triage(
        &target_url,
        &mutated_payload,
        &anomaly_type,
        &baseline_vs_anomaly,
    )
    .await;

    let report_md = build_report_markdown(
        &target_url,
        &mutated_payload,
        &anomaly_type,
        &baseline_vs_anomaly,
        triage.as_ref(),
    );

    let reports_dir = Path::new("reports");
    if !reports_dir.exists() {
        let _ = std::fs::create_dir_all(reports_dir);
    }
    let name = report_filename();
    let path = reports_dir.join(&name);
    if std::fs::write(&path, report_md).is_err() {
        tracing::warn!(target: "reporter", path = %path.display(), "failed to write bug report");
        return;
    }

    notify_webhook(&name).await;
}

/// Queues report generation on the runtime: LLM triage (with timeout + JSON parse), Markdown write,
/// then NOTIFY_URL retries — **does not block** the caller (no `.await` needed).
pub fn generate_bug_report(
    target_url: &str,
    mutated_payload: &str,
    anomaly_type: &str,
    baseline_vs_anomaly: &str,
) {
    let target_url = target_url.to_string();
    let mutated_payload = mutated_payload.to_string();
    let anomaly_type = anomaly_type.to_string();
    let baseline_vs_anomaly = baseline_vs_anomaly.to_string();
    tokio::spawn(async move {
        generate_bug_report_worker(
            target_url,
            mutated_payload,
            anomaly_type,
            baseline_vs_anomaly,
        )
        .await;
    });
}

/// Same pipeline as [`generate_bug_report`] but **awaitable** (e.g. tests or admin tools).
pub async fn generate_bug_report_blocking(
    target_url: &str,
    mutated_payload: &str,
    anomaly_type: &str,
    baseline_vs_anomaly: &str,
) -> Option<std::path::PathBuf> {
    let triage = fetch_bug_report_triage(
        target_url,
        mutated_payload,
        anomaly_type,
        baseline_vs_anomaly,
    )
    .await;

    let report_md = build_report_markdown(
        target_url,
        mutated_payload,
        anomaly_type,
        baseline_vs_anomaly,
        triage.as_ref(),
    );

    let reports_dir = Path::new("reports");
    if !reports_dir.exists() {
        let _ = std::fs::create_dir_all(reports_dir);
    }
    let name = report_filename();
    let path = reports_dir.join(&name);
    if std::fs::write(&path, report_md).is_err() {
        return None;
    }

    notify_webhook(&name).await;
    Some(path)
}
