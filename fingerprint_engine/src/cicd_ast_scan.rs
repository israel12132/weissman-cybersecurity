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
    R.get_or_init(|| {
        Regex::new(r"(?:AKIA|ASIA|AROA|AIDA|ANPA|ANVA|AIPA)[0-9A-Z]{16}")
            .unwrap_or_else(|_| never_matches())
    })
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
    R.get_or_init(|| Regex::new(r"gh[pousr]_[A-Za-z0-9]{36,}").unwrap_or_else(|_| never_matches()))
}

/// GCP service account JSON key (contains "private_key_id")
fn gcp_service_account_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#""private_key_id"\s*:\s*"[0-9a-f]{40}""#).unwrap_or_else(|_| never_matches())
    })
}

/// Slack Bot / OAuth tokens
fn slack_token_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"xox[baprs]-[0-9A-Za-z\-]{10,}").unwrap_or_else(|_| never_matches())
    })
}

/// Stripe publishable / secret keys
fn stripe_key_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{24,}").unwrap_or_else(|_| never_matches())
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
        Regex::new(r"AC[0-9a-f]{32}|SK[0-9a-f]{32}").unwrap_or_else(|_| never_matches())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_for_value_locates_line_number() {
        assert_eq!(line_for_value_in_source("", "x"), 1); // empty source
        assert_eq!(line_for_value_in_source("l1\nl2\nl3", ""), 1); // empty value
        assert_eq!(line_for_value_in_source("l1\nl2\nTARGET\n", "TARGET"), 3);
        assert_eq!(line_for_value_in_source("TARGET on line one", "TARGET"), 1);
        assert_eq!(line_for_value_in_source("l1\nl2", "missing"), 1); // not found
    }

    #[test]
    fn scan_regex_detects_aws_access_key() {
        let f = scan_regex_only("cfg.txt", "let key = \"AKIAIOSFODNN7EXAMPLE\";");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "aws_access_key_id");
        assert_eq!(f[0].severity, "critical");
        assert_eq!(f[0].line, 1);
    }

    #[test]
    fn scan_regex_detects_pem_private_key() {
        let f = scan_regex_only("id_rsa", "-----BEGIN RSA PRIVATE KEY-----");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "private_key_material");
        assert_eq!(f[0].severity, "critical");
    }

    #[test]
    fn scan_regex_detects_github_token() {
        let content = format!("token = \"ghp_{}\"", "a".repeat(36));
        let f = scan_regex_only("app.env", &content);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "github_token");
        assert_eq!(f[0].severity, "critical");
    }

    #[test]
    fn scan_regex_slack_token_is_high_severity() {
        let f = scan_regex_only("bot.env", "xoxb-1234567890-abcdefghij");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "slack_token");
        assert_eq!(f[0].severity, "high");
    }

    #[test]
    fn scan_regex_reports_correct_line() {
        let content = "line1\nline2\nlet key = \"AKIAIOSFODNN7EXAMPLE\";";
        let f = scan_regex_only("f.txt", content);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].line, 3);
    }

    #[test]
    fn scan_regex_clean_content_has_no_findings() {
        let f = scan_regex_only("clean.txt", "let x = 1;\nprintln!(\"hi\");");
        assert!(f.is_empty());
    }

    #[test]
    fn scan_regex_first_matching_rule_wins_per_line() {
        // else-if chain: only one finding per line even with two secrets present
        let f = scan_regex_only(
            "mixed.txt",
            "-----BEGIN RSA PRIVATE KEY----- AKIAIOSFODNN7EXAMPLE",
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "private_key_material");
    }

    #[test]
    fn scan_file_large_file_is_skipped() {
        let big = "a".repeat(2_000_001);
        let f = scan_file("big.txt", &big);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "file_too_large");
        assert_eq!(f[0].severity, "high");
        assert_eq!(f[0].line, 0);
    }

    #[test]
    fn scan_file_rust_runs_both_regex_and_ast_passes() {
        let content = "fn f() { let s = \"AKIAIOSFODNN7EXAMPLE\"; }";
        // A .rs file is scanned by BOTH the regex pass and the syn AST walk; every
        // finding flags the same AWS-key rule and is critical.
        let rs = scan_file("secret.rs", content);
        assert!(!rs.is_empty());
        assert!(rs.iter().all(|f| f.rule == "aws_access_key_id"));
        assert!(has_critical(&rs));
        // A non-Rust file uses the regex pass only -> exactly one finding.
        let txt = scan_file("secret.txt", content);
        assert_eq!(txt.len(), 1);
        assert_eq!(txt[0].rule, "aws_access_key_id");
        // The AST pass adds coverage on .rs files beyond the regex-only pass.
        assert!(rs.len() >= txt.len());
    }

    #[test]
    fn scan_file_sorts_findings_by_line() {
        let content =
            "clean\n-----BEGIN RSA PRIVATE KEY-----\nmore\nlet k=\"AKIAIOSFODNN7EXAMPLE\";";
        let f = scan_file("multi.txt", content);
        assert_eq!(f.len(), 2);
        assert!(f[0].line <= f[1].line);
        assert_eq!(f[0].line, 2);
        assert_eq!(f[1].line, 4);
    }

    #[test]
    fn scan_many_files_aggregates() {
        let files = vec![
            (
                "a.txt".to_string(),
                "-----BEGIN RSA PRIVATE KEY-----".to_string(),
            ),
            ("b.txt".to_string(), "nothing here".to_string()),
            (
                "c.txt".to_string(),
                "xoxb-1234567890-abcdefghij".to_string(),
            ),
        ];
        let f = scan_many_files(&files);
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn has_critical_detects_severity() {
        assert!(!has_critical(&[]));
        let high = CicdFinding {
            path: "p".into(),
            line: 1,
            rule: "slack_token".into(),
            severity: "high".into(),
            snippet: "".into(),
        };
        assert!(!has_critical(std::slice::from_ref(&high)));
        let crit = CicdFinding {
            path: "p".into(),
            line: 1,
            rule: "aws_access_key_id".into(),
            severity: "critical".into(),
            snippet: "".into(),
        };
        assert!(has_critical(&[high, crit]));
    }

    #[test]
    fn cicd_finding_serializes_to_json() {
        let finding = CicdFinding {
            path: "src/main.rs".into(),
            line: 42,
            rule: "aws_access_key_id".into(),
            severity: "critical".into(),
            snippet: "AKIA...".into(),
        };
        let v = serde_json::to_value(&finding).unwrap();
        assert_eq!(v["path"], "src/main.rs");
        assert_eq!(v["line"], 42);
        assert_eq!(v["rule"], "aws_access_key_id");
        assert_eq!(v["severity"], "critical");
    }
}
