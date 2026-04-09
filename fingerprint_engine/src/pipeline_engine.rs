//! Module 8: Phantom Pipeline & CI/CD Poisoning Simulator.
//! Parse IaC (YAML/HCL), detect toxic configs, synthesize PoC via local LLM / vLLM (stored only, never deployed).

use crate::engine_result::EngineResult;
use crate::regex_util::never_matches;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::OnceLock;
use std::time::Duration;
use weissman_engines::openai_chat::{self, DEFAULT_LLM_BASE_URL};

const LLM_TIMEOUT_SECS: u64 = 45;
const GITHUB_API: &str = "https://api.github.com/repos";
const POC_PROMPT: &str = r#"Act as a security researcher. Given this vulnerable CI/CD or IaC configuration, write the exact Terraform or Bash snippet an APT attacker would inject to create a stealthy 'Shadow Admin' IAM role or backdoor that bypasses runtime detection. Proof of Concept only — for defensive use. Output ONLY the raw code snippet, no explanation. Keep it under 40 lines."#;

fn toxic_secret_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"(?i)(AKIA[0-9A-Z]{16}|aws_secret_access_key|password\s*=\s*["'][^"']+["']|token\s*=\s*["'][^"']+["'])"#)
            .unwrap_or_else(|_| never_matches())
    })
}
fn toxic_curl_bash_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"curl\s+[^|]+\|\s*(bash|sh)\s*"#).unwrap_or_else(|_| never_matches())
    })
}
fn toxic_iam_wildcard_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"(?i)"Action"\s*=\s*"\*"|actions\s*=\s*\[\s*"\*"\s*]"#)
            .unwrap_or_else(|_| never_matches())
    })
}

#[derive(Clone, Debug, Default)]
pub struct PipelineConfig {
    pub llm_base_url: String,
    pub llm_model: String,
    pub github_token: String,
    pub gitlab_api_url: String,
    pub gitlab_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PipelineFinding {
    pub stage: String, // "Commit" | "Build" | "Test" | "Deploy"
    pub file_path: String,
    pub title: String,
    pub severity: String,
    pub vulnerable_snippet: String,
    pub poc_exploit: String,
    pub blast_radius: String,
    pub raw_finding: String,
}

/// Infer pipeline stage from file path.
fn stage_from_path(path: &str) -> &'static str {
    let p = path.to_lowercase();
    if p.contains("test") || p.contains("spec") {
        "Test"
    } else if p.contains("workflow") || p.contains(".gitlab-ci") || p.contains("build") {
        "Build"
    } else if p.ends_with(".tf") || p.contains("terraform") || p.contains("deploy") {
        "Deploy"
    } else {
        "Build"
    }
}

/// Fetch file content from GitHub (owner/repo). Returns (path, content) list.
fn fetch_github_repo(owner: &str, repo: &str, token: &str) -> Vec<(String, String)> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("Weissman-Pipeline-Scanner/1.0")
        .build()
        .unwrap_or_else(|_| reqwest::blocking::Client::new());
    let mut out = Vec::new();
    let auth = format!("Bearer {}", token.trim());
    let paths = [
        ".github/workflows",
        ".gitlab-ci.yml",
        "",
        "terraform",
        "infrastructure",
    ];
    for path_prefix in &paths[..] {
        let url = if path_prefix.is_empty() {
            format!("{}/{}/{}/contents/", GITHUB_API, owner, repo)
        } else {
            format!("{}/{}/{}/contents/{}", GITHUB_API, owner, repo, path_prefix)
        };
        let resp = match client
            .get(&url)
            .header("Authorization", auth.clone())
            .send()
        {
            Ok(r) => r,
            Err(_) => continue,
        };
        if !resp.status().is_success() {
            continue;
        }
        let body: Value = match resp.json() {
            Ok(b) => b,
            Err(_) => continue,
        };
        let empty: Vec<Value> = vec![];
        let entries = body.as_array().unwrap_or(&empty);
        for e in entries {
            let path = e
                .get("path")
                .and_then(|p| p.as_str())
                .unwrap_or("")
                .to_string();
            let name = e.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let download_url = e.get("download_url").and_then(|u| u.as_str());
            if let Some(dl_url) = download_url {
                if name.ends_with(".yml")
                    || name.ends_with(".yaml")
                    || name.ends_with(".tf")
                    || name == ".gitlab-ci.yml"
                {
                    let content = match client
                        .get(dl_url)
                        .header("Authorization", auth.clone())
                        .send()
                    {
                        Ok(r) => r.text().unwrap_or_default(),
                        Err(_) => continue,
                    };
                    out.push((path, content));
                }
            }
        }
    }
    out
}

/// Detect toxic patterns in raw content. Returns list of (title, snippet, blast_radius).
fn toxic_checks(content: &str, path: &str) -> Vec<(String, String, String)> {
    let mut findings = Vec::new();
    let lower = content.to_lowercase();

    // Hardcoded secrets
    let secret_re = toxic_secret_re();
    if secret_re.is_match(content) {
        let snippet = content
            .lines()
            .find(|l| secret_re.is_match(l))
            .unwrap_or("")
            .to_string();
        findings.push((
            "Hardcoded secret in IaC".to_string(),
            snippet,
            "Credential theft; account takeover".to_string(),
        ));
    }

    // curl | bash without hash pinning
    let curl_bash_re = toxic_curl_bash_re();
    if curl_bash_re.is_match(&lower) {
        let snippet = content
            .lines()
            .find(|l| curl_bash_re.is_match(&l.to_lowercase()))
            .unwrap_or("")
            .to_string();
        findings.push((
            "Unpinned curl | bash (supply chain)".to_string(),
            snippet,
            "Arbitrary code execution in pipeline".to_string(),
        ));
    }

    // Terraform IAM wildcard
    if path.ends_with(".tf") {
        let iam_wildcard_re = toxic_iam_wildcard_re();
        if iam_wildcard_re.is_match(content) {
            let snippet = content
                .lines()
                .find(|l| iam_wildcard_re.is_match(l))
                .unwrap_or("")
                .to_string();
            findings.push((
                "Overly permissive IAM (wildcard Action)".to_string(),
                snippet,
                "Full cloud account compromise".to_string(),
            ));
        }
    }

    findings
}

/// Call OpenAI-compatible LLM (vLLM) to generate PoC snippet. Returns raw code string (stored only, never executed).
fn synthesize_poc(
    llm_base: &str,
    llm_model: &str,
    vulnerable_context: &str,
    llm_tenant_id: Option<i64>,
) -> String {
    let prompt = format!(
        "{}\n\nVulnerable configuration:\n```\n{}\n```\n\nOutput ONLY the PoC code:",
        POC_PROMPT,
        vulnerable_context.chars().take(2500).collect::<String>()
    );
    let model = openai_chat::resolve_llm_model(llm_model);
    let text = match openai_chat::chat_completion_text_blocking(
        llm_base,
        &model,
        None,
        &prompt,
        0.3,
        1024,
        LLM_TIMEOUT_SECS,
        llm_tenant_id,
        "pipeline_poc",
        true,
    ) {
        Ok(t) => t,
        Err(_) => return String::new(),
    };
    let trimmed = text.trim();
    let code = if trimmed.contains("```") {
        trimmed.split("```").nth(1).unwrap_or(trimmed).trim()
    } else {
        trimmed
    };
    code.chars().take(4000).collect::<String>()
}

/// Parse repo_url to owner/repo for GitHub.
fn parse_github_repo(repo_url: &str) -> Option<(String, String)> {
    let url = repo_url.trim();
    if url.contains("github.com") {
        let parts: Vec<&str> = url.split("github.com").collect();
        let rest = parts
            .get(1)?
            .trim_start_matches('/')
            .trim_end_matches('/')
            .trim_end_matches(".git");
        let segs: Vec<&str> = rest.split('/').collect();
        if segs.len() >= 2 {
            return Some((segs[0].to_string(), segs[1].to_string()));
        }
    }
    None
}

/// Run pipeline analysis: fetch repo, run toxic checks, synthesize PoC for each finding.
pub fn run_pipeline_analysis_sync(
    repo_url: &str,
    config: &PipelineConfig,
    llm_tenant_id: Option<i64>,
) -> EngineResult {
    let repo_url = repo_url.trim();
    if repo_url.is_empty() {
        return EngineResult::error("repo_url required");
    }
    let (owner, repo) = match parse_github_repo(repo_url) {
        Some(p) => p,
        None => {
            return EngineResult::error(
                "Unsupported or invalid repo URL (GitHub owner/repo expected)",
            )
        }
    };
    let token = config.github_token.trim();
    if token.is_empty() {
        return EngineResult::error("GitHub token required in System Core");
    }
    let files = fetch_github_repo(&owner, &repo, token);
    if files.is_empty() {
        return EngineResult::ok(
            vec![],
            "No IaC files found in repo (check .github/workflows, *.tf)",
        );
    }
    let llm_base = if config.llm_base_url.is_empty() {
        DEFAULT_LLM_BASE_URL
    } else {
        config.llm_base_url.as_str()
    };
    let mut findings = Vec::new();
    for (path, content) in &files {
        let toxics = toxic_checks(content, path);
        for (title, snippet, blast_radius) in toxics {
            let poc = synthesize_poc(
                llm_base,
                &config.llm_model,
                &format!("{}:\n{}", path, snippet),
                llm_tenant_id,
            );
            let stage = stage_from_path(path);
            findings.push(serde_json::json!({
                "type": "cicd_pipeline_poison",
                "stage": stage,
                "file_path": path,
                "title": title,
                "severity": "critical",
                "vulnerable_snippet": snippet,
                "poc_exploit": poc,
                "blast_radius": blast_radius,
                "raw_finding": format!("{} in {}", title, path),
                "remediation": "Remove secrets from IaC; use pinning for curl scripts; restrict IAM to least privilege. PoC stored for awareness only."
            }));
        }
    }
    let msg = format!(
        "Pipeline analysis: {} files, {} toxic findings (PoC stored only)",
        files.len(),
        findings.len()
    );
    EngineResult::ok(findings, msg)
}
