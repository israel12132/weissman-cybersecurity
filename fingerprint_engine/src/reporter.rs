//! Local bug bounty report generation. LLM-assisted triage (vLLM) with static fallback;
//! HackerOne/Bugcrowd-style Markdown to `reports/`, then optional NOTIFY_URL webhook (retries intact).

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
        let rem = format!("\n---\n\n## Remediation\n\n{}\n\n---\n\n", t.remediation);
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

/// Resolve the reports output directory.
///
/// Priority:
///   1. `WEISSMAN_REPORTS_DIR` environment variable (absolute or relative path).
///   2. A `reports/` directory next to the running binary's location.
///   3. Fall back to `reports/` relative to the current working directory.
fn reports_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("WEISSMAN_REPORTS_DIR") {
        let p = std::path::PathBuf::from(dir.trim());
        if !p.as_os_str().is_empty() {
            return p;
        }
    }
    // Resolve relative to the binary's own directory so the path is stable
    // regardless of where the binary is invoked from.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            return parent.join("reports");
        }
    }
    // Last-resort fallback
    std::path::PathBuf::from("reports")
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

fn report_pdf_filename(markdown_name: &str) -> String {
    if let Some(stem) = markdown_name.strip_suffix(".md") {
        format!("{stem}.pdf")
    } else {
        format!("{markdown_name}.pdf")
    }
}

fn pdf_escape(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '(' => escaped.push_str("\\("),
            ')' => escaped.push_str("\\)"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c.is_control() => escaped.push(' '),
            c => escaped.push(c),
        }
    }
    escaped
}

fn cvss_score_from_severity(severity: &str) -> f32 {
    match severity.trim().to_lowercase().as_str() {
        "critical" => 9.8,
        "high" => 8.2,
        "medium" => 6.4,
        "low" => 3.7,
        other => {
            tracing::warn!(target: "reporter", severity = other, "unknown severity for anomaly pdf; using fallback cvss");
            5.0
        }
    }
}

fn wrap_for_pdf(text: &str, max_chars: usize) -> Vec<String> {
    let mut wrapped: Vec<String> = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            wrapped.push(String::new());
            continue;
        }
        let mut current = String::new();
        for token in line.split_whitespace() {
            if token.len() > max_chars {
                if !current.is_empty() {
                    wrapped.push(std::mem::take(&mut current));
                }
                let mut start = 0usize;
                let chars: Vec<char> = token.chars().collect();
                while start < chars.len() {
                    let end = (start + max_chars).min(chars.len());
                    wrapped.push(chars[start..end].iter().collect());
                    start = end;
                }
                continue;
            }
            let next_len = if current.is_empty() {
                token.len()
            } else {
                current.len() + 1 + token.len()
            };
            if next_len > max_chars && !current.is_empty() {
                wrapped.push(std::mem::take(&mut current));
            }
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(token);
        }
        if !current.is_empty() {
            wrapped.push(current);
        }
    }
    wrapped
}

fn build_anomaly_pdf(
    target_url: &str,
    anomaly_type: &str,
    baseline_vs_anomaly: &str,
    severity: &str,
    remediation: &str,
) -> Vec<u8> {
    let cvss = cvss_score_from_severity(severity);
    let mut lines = vec![
        "Weissman Fuzzer Anomaly Report".to_string(),
        format!("Timestamp: {}", format_timestamp()),
        String::new(),
        format!("Target URL: {target_url}"),
        format!("Anomaly Type: {anomaly_type}"),
        format!("Severity: {}", severity.to_uppercase()),
        format!("Estimated CVSS: {cvss:.1}"),
        String::new(),
        "Baseline vs Anomaly".to_string(),
    ];
    lines.extend(wrap_for_pdf(baseline_vs_anomaly, 90));
    lines.push(String::new());
    lines.push("Recommended Remediation".to_string());
    lines.extend(wrap_for_pdf(remediation, 90));

    // Single-page A4-ish layout using 16px line spacing from y=750. Keep hard cap
    // so content never overflows the page box and corrupts rendering.
    const MAX_LINES: usize = 44;
    if lines.len() > MAX_LINES {
        lines.truncate(MAX_LINES - 1);
        lines.push("... (truncated)".to_string());
    }

    let mut stream = String::from("BT\n/F1 16 Tf\n72 750 Td\n");
    for (idx, line) in lines.iter().enumerate() {
        if idx == 1 {
            stream.push_str("/F1 11 Tf\n");
        }
        if idx > 0 {
            stream.push_str("0 -16 Td\n");
        }
        let escaped = pdf_escape(line);
        stream.push_str(&format!("({escaped}) Tj\n"));
    }
    stream.push_str("ET");

    let mut out = Vec::new();
    let mut offsets: Vec<usize> = vec![0];
    out.extend_from_slice(b"%PDF-1.4\n");
    offsets.push(out.len());
    out.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    offsets.push(out.len());
    out.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
    offsets.push(out.len());
    out.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n",
    );
    offsets.push(out.len());
    out.extend_from_slice(
        format!(
            "4 0 obj\n<< /Length {} >>\nstream\n{}\nendstream\nendobj\n",
            stream.len(),
            stream
        )
        .as_bytes(),
    );
    offsets.push(out.len());
    out.extend_from_slice(
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
    );
    let xref_offset = out.len();
    out.extend_from_slice(b"xref\n0 6\n0000000000 65535 f \n");
    for off in offsets.iter().skip(1).take(5) {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
            xref_offset
        )
        .as_bytes(),
    );
    out
}

fn write_anomaly_pdf_sidecar(
    reports_dir_path: &std::path::Path,
    markdown_name: &str,
    target_url: &str,
    anomaly_type: &str,
    baseline_vs_anomaly: &str,
    triage: Option<&BugReportTriage>,
) {
    let severity = triage
        .map(|t| t.severity.clone())
        .unwrap_or_else(|| "Medium".to_string());
    let remediation = triage
        .map(|t| t.remediation.clone())
        .unwrap_or_else(|| {
            "Validate and sanitize inputs, enforce strict schema checks, apply defensive timeouts, and retest after fix."
                .to_string()
        });
    let pdf_bytes = build_anomaly_pdf(
        target_url,
        anomaly_type,
        baseline_vs_anomaly,
        &severity,
        &remediation,
    );
    let pdf_name = report_pdf_filename(markdown_name);
    let pdf_path = reports_dir_path.join(pdf_name);
    if let Err(error) = std::fs::write(&pdf_path, pdf_bytes) {
        tracing::warn!(
            target: "reporter",
            path = %pdf_path.display(),
            error = %error,
            "failed to write anomaly pdf sidecar"
        );
    }
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

    let reports_dir_path = reports_dir();
    if !reports_dir_path.exists() {
        let _ = std::fs::create_dir_all(&reports_dir_path);
    }
    let name = report_filename();
    let path = reports_dir_path.join(&name);
    if std::fs::write(&path, report_md).is_err() {
        tracing::warn!(target: "reporter", path = %path.display(), "failed to write bug report");
        return;
    }
    write_anomaly_pdf_sidecar(
        &reports_dir_path,
        &name,
        &target_url,
        &anomaly_type,
        &baseline_vs_anomaly,
        triage.as_ref(),
    );

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

    let reports_dir_path = reports_dir();
    if !reports_dir_path.exists() {
        let _ = std::fs::create_dir_all(&reports_dir_path);
    }
    let name = report_filename();
    let path = reports_dir_path.join(&name);
    if std::fs::write(&path, report_md).is_err() {
        return None;
    }
    write_anomaly_pdf_sidecar(
        &reports_dir_path,
        &name,
        target_url,
        anomaly_type,
        baseline_vs_anomaly,
        triage.as_ref(),
    );

    notify_webhook(&name).await;
    Some(path)
}
