//! Phase 6: Sub-millisecond structural + pattern scan for CI/CD gate (fail build on critical).

use crate::regex_util::never_matches;
use regex::Regex;
use std::sync::OnceLock;
use syn::visit::Visit;
use syn::LitStr;

#[derive(Debug, Clone, serde::Serialize)]
pub struct CicdFinding {
    pub path: String,
    pub line: u32,
    pub rule: String,
    pub severity: String,
    pub snippet: String,
}

fn aws_key_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    // AWS Access Key IDs (AKIA = long-term, ASIA = session)
    R.get_or_init(|| Regex::new(r"(?:AKIA|ASIA|AROA|AIDA|ANPA|ANVA|AIPA)[0-9A-Z]{16}").unwrap_or_else(|_| never_matches()))
}

fn pem_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----")
            .unwrap_or_else(|_| never_matches())
    })
}

fn sqli_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)(union\s+select|'?\s*or\s+1\s*=\s*1|;\s*drop\s+table|exec\s*\()")
            .unwrap_or_else(|_| never_matches())
    })
}

fn hardcoded_secret_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"(?i)(api[_-]?key|secret[_-]?key|private[_-]?key|password|passwd|pwd|token|bearer|auth[_-]?token|access[_-]?key|client[_-]?secret|db[_-]?password|database[_-]?url)\s*[=:]\s*['"][^'"]{12,}['"]"#)
            .unwrap_or_else(|_| never_matches())
    })
}

/// GitHub Personal Access Token (classic and fine-grained)
fn github_token_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"gh[pousr]_[A-Za-z0-9]{36,}")
            .unwrap_or_else(|_| never_matches())
    })
}

/// GCP service account JSON key (contains "private_key_id")
fn gcp_service_account_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#""private_key_id"\s*:\s*"[0-9a-f]{40}""#)
            .unwrap_or_else(|_| never_matches())
    })
}

/// Slack Bot / OAuth tokens
fn slack_token_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"xox[baprs]-[0-9A-Za-z\-]{10,}")
            .unwrap_or_else(|_| never_matches())
    })
}

/// Stripe publishable / secret keys
fn stripe_key_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{24,}")
            .unwrap_or_else(|_| never_matches())
    })
}

/// Generic high-entropy JWT secret assignments (jwt_secret = "...", JWT_SECRET = "...")
fn jwt_secret_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"(?i)jwt[_-]?secret\s*[=:]\s*['"][^'"]{16,}['"]"#)
            .unwrap_or_else(|_| never_matches())
    })
}

/// Twilio Account SID and Auth Token
fn twilio_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"AC[0-9a-f]{32}|SK[0-9a-f]{32}")
            .unwrap_or_else(|_| never_matches())
    })
}

fn line_for_value_in_source(src: &str, val: &str) -> u32 {
    if val.is_empty() {
        return 1;
    }
    src.find(val)
        .map(|pos| src[..pos].lines().count() as u32 + 1)
        .unwrap_or(1)
}

struct RustStringVisitor<'a> {
    path: &'a str,
    content: &'a str,
    findings: &'a mut Vec<CicdFinding>,
}

impl<'ast, 'a> Visit<'ast> for RustStringVisitor<'a> {
    fn visit_lit_str(&mut self, s: &'ast LitStr) {
        let v = s.value();
        let line = line_for_value_in_source(self.content, &v);
        if pem_re().is_match(&v) {
            self.findings.push(CicdFinding {
                path: self.path.into(),
                line,
                rule: "private_key_material".into(),
                severity: "critical".into(),
                snippet: v.chars().take(200).collect(),
            });
        }
        if aws_key_re().is_match(&v) {
            self.findings.push(CicdFinding {
                path: self.path.into(),
                line,
                rule: "aws_access_key_id".into(),
                severity: "critical".into(),
                snippet: v.chars().take(200).collect(),
            });
        }
        if sqli_re().is_match(&v) {
            self.findings.push(CicdFinding {
                path: self.path.into(),
                line,
                rule: "sql_injection_pattern".into(),
                severity: "critical".into(),
                snippet: v.chars().take(200).collect(),
            });
        }
        if hardcoded_secret_re().is_match(&v) {
            self.findings.push(CicdFinding {
                path: self.path.into(),
                line,
                rule: "hardcoded_credential".into(),
                severity: "critical".into(),
                snippet: v.chars().take(200).collect(),
            });
        }
        if github_token_re().is_match(&v) {
            self.findings.push(CicdFinding {
                path: self.path.into(),
                line,
                rule: "github_token".into(),
                severity: "critical".into(),
                snippet: v.chars().take(200).collect(),
            });
        }
        if gcp_service_account_re().is_match(&v) {
            self.findings.push(CicdFinding {
                path: self.path.into(),
                line,
                rule: "gcp_service_account_key".into(),
                severity: "critical".into(),
                snippet: v.chars().take(200).collect(),
            });
        }
        if slack_token_re().is_match(&v) {
            self.findings.push(CicdFinding {
                path: self.path.into(),
                line,
                rule: "slack_token".into(),
                severity: "high".into(),
                snippet: v.chars().take(200).collect(),
            });
        }
        if stripe_key_re().is_match(&v) {
            self.findings.push(CicdFinding {
                path: self.path.into(),
                line,
                rule: "stripe_api_key".into(),
                severity: "critical".into(),
                snippet: v.chars().take(200).collect(),
            });
        }
        if jwt_secret_re().is_match(&v) {
            self.findings.push(CicdFinding {
                path: self.path.into(),
                line,
                rule: "hardcoded_jwt_secret".into(),
                severity: "critical".into(),
                snippet: v.chars().take(200).collect(),
            });
        }
        if twilio_re().is_match(&v) {
            self.findings.push(CicdFinding {
                path: self.path.into(),
                line,
                rule: "twilio_credential".into(),
                severity: "high".into(),
                snippet: v.chars().take(200).collect(),
            });
        }
        syn::visit::visit_lit_str(self, s);
    }
}

fn scan_regex_only(path: &str, content: &str) -> Vec<CicdFinding> {
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let ln = (i + 1) as u32;
        if pem_re().is_match(line) {
            out.push(CicdFinding {
                path: path.into(),
                line: ln,
                rule: "private_key_material".into(),
                severity: "critical".into(),
                snippet: line.chars().take(200).collect(),
            });
        } else if aws_key_re().is_match(line) {
            out.push(CicdFinding {
                path: path.into(),
                line: ln,
                rule: "aws_access_key_id".into(),
                severity: "critical".into(),
                snippet: line.chars().take(200).collect(),
            });
        } else if github_token_re().is_match(line) {
            out.push(CicdFinding {
                path: path.into(),
                line: ln,
                rule: "github_token".into(),
                severity: "critical".into(),
                snippet: line.chars().take(200).collect(),
            });
        } else if gcp_service_account_re().is_match(line) {
            out.push(CicdFinding {
                path: path.into(),
                line: ln,
                rule: "gcp_service_account_key".into(),
                severity: "critical".into(),
                snippet: line.chars().take(200).collect(),
            });
        } else if stripe_key_re().is_match(line) {
            out.push(CicdFinding {
                path: path.into(),
                line: ln,
                rule: "stripe_api_key".into(),
                severity: "critical".into(),
                snippet: line.chars().take(200).collect(),
            });
        } else if slack_token_re().is_match(line) {
            out.push(CicdFinding {
                path: path.into(),
                line: ln,
                rule: "slack_token".into(),
                severity: "high".into(),
                snippet: line.chars().take(200).collect(),
            });
        } else if twilio_re().is_match(line) {
            out.push(CicdFinding {
                path: path.into(),
                line: ln,
                rule: "twilio_credential".into(),
                severity: "high".into(),
                snippet: line.chars().take(200).collect(),
            });
        } else if jwt_secret_re().is_match(line) {
            out.push(CicdFinding {
                path: path.into(),
                line: ln,
                rule: "hardcoded_jwt_secret".into(),
                severity: "critical".into(),
                snippet: line.chars().take(200).collect(),
            });
        } else if sqli_re().is_match(line) {
            out.push(CicdFinding {
                path: path.into(),
                line: ln,
                rule: "sql_injection_pattern".into(),
                severity: "critical".into(),
                snippet: line.chars().take(200).collect(),
            });
        } else if hardcoded_secret_re().is_match(line) {
            out.push(CicdFinding {
                path: path.into(),
                line: ln,
                rule: "hardcoded_credential".into(),
                severity: "critical".into(),
                snippet: line.chars().take(200).collect(),
            });
        }
    }
    out
}

fn scan_rust_ast(path: &str, content: &str, base: &mut Vec<CicdFinding>) {
    let Ok(file) = syn::parse_file(content) else {
        return;
    };
    let mut v = RustStringVisitor {
        path,
        content,
        findings: base,
    };
    v.visit_file(&file);
}

/// Full scan: regex pass on entire buffer (fast), plus `syn` walk for Rust string literals.
pub fn scan_file(path: &str, content: &str) -> Vec<CicdFinding> {
    if content.len() > 2_000_000 {
        return vec![CicdFinding {
            path: path.into(),
            line: 0,
            rule: "file_too_large".into(),
            severity: "high".into(),
            snippet: "file skipped (>2MB)".into(),
        }];
    }
    let lower = path.to_lowercase();
    let mut hits = scan_regex_only(path, content);
    if lower.ends_with(".rs") {
        scan_rust_ast(path, content, &mut hits);
    }
    hits.sort_by(|a, b| a.line.cmp(&b.line));
    hits.dedup_by(|a, b| a.line == b.line && a.rule == b.rule);
    hits
}

pub fn scan_many_files(files: &[(String, String)]) -> Vec<CicdFinding> {
    let mut all = Vec::new();
    for (p, c) in files {
        all.extend(scan_file(p, c));
    }
    all
}

pub fn has_critical(findings: &[CicdFinding]) -> bool {
    findings.iter().any(|f| f.severity == "critical")
}
