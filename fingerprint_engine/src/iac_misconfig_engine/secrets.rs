//! Cross-framework secret scanner: detects hard-coded credentials in any IaC artifact using
//! high-signal provider patterns plus an entropy-filtered generic assignment detector. Values are
//! always masked in the evidence — the engine reports the location, never the full secret.

use super::model::{Finding, PolicyMeta, Severity};
use regex::Regex;
use std::sync::OnceLock;

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "secrets", provider: "generic",
            description: $desc,
            remediation: "Remove the secret from source, rotate it immediately, and load it at runtime from a secret manager (Vault, AWS/GCP/Azure secret stores) or CI secret store.",
            mitre: "T1552.001", cwe: "CWE-798",
            references: &["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/", "https://cwe.mitre.org/data/definitions/798.html"],
            compliance: &["NIST-IA-5", "PCI-DSS-8.2.1", "PCI-DSS-3.4", "SOC2-CC6.1", "ISO27001-A.9.4.3", "MITRE-T1552.001"],
        }
    };
}

pub const AWS_KEY: PolicyMeta = pol!("WZ-SEC-AWS-001", "AWS access key id committed in source", Critical, "An AWS access key id (AKIA…) is hard-coded, granting programmatic access if paired with its secret.");
pub const PRIVATE_KEY: PolicyMeta = pol!(
    "WZ-SEC-PK-001",
    "Private key material committed in source",
    Critical,
    "A PEM private key block is embedded in source, exposing TLS/SSH/signing identities."
);
pub const GITHUB_PAT: PolicyMeta = pol!(
    "WZ-SEC-GH-001",
    "GitHub token committed in source",
    Critical,
    "A GitHub personal-access/app token is hard-coded, allowing repo and CI compromise."
);
pub const GCP_SA: PolicyMeta = pol!(
    "WZ-SEC-GCP-001",
    "GCP service-account key committed in source",
    Critical,
    "A Google Cloud service-account JSON key is embedded, granting cloud access."
);
pub const GOOGLE_API: PolicyMeta = pol!(
    "WZ-SEC-GOOG-001",
    "Google API key committed in source",
    High,
    "A Google API key (AIza…) is hard-coded."
);
pub const SLACK: PolicyMeta = pol!(
    "WZ-SEC-SLACK-001",
    "Slack token committed in source",
    High,
    "A Slack token (xox…) is hard-coded."
);
pub const STRIPE: PolicyMeta = pol!(
    "WZ-SEC-STRIPE-001",
    "Stripe live secret key committed in source",
    Critical,
    "A Stripe live secret key (sk_live_…) is hard-coded."
);
pub const NPM: PolicyMeta = pol!(
    "WZ-SEC-NPM-001",
    "npm token committed in source",
    High,
    "An npm automation token (npm_…) is hard-coded."
);
pub const JWT: PolicyMeta = pol!(
    "WZ-SEC-JWT-001",
    "JWT committed in source",
    Medium,
    "A JSON Web Token is embedded; it may carry valid claims/credentials."
);
pub const GENERIC: PolicyMeta = pol!("WZ-SEC-GEN-001", "Hard-coded credential (generic high-entropy)", High, "A password/secret/token assignment holds a high-entropy literal value rather than a reference.");

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![
        AWS_KEY,
        PRIVATE_KEY,
        GITHUB_PAT,
        GCP_SA,
        GOOGLE_API,
        SLACK,
        STRIPE,
        NPM,
        JWT,
        GENERIC,
    ]
}

struct Rule {
    re: Regex,
    /// capture-group index that holds the secret value (0 = whole match).
    grp: usize,
    pol: PolicyMeta,
    generic: bool,
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let mut v = Vec::new();
        let mut push = |pat: &str, grp: usize, pol: PolicyMeta, generic: bool| {
            if let Ok(re) = Regex::new(pat) {
                v.push(Rule { re, grp, pol, generic });
            }
        };
        push(r"AKIA[0-9A-Z]{16}", 0, AWS_KEY, false);
        push(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", 0, PRIVATE_KEY, false);
        push(r"(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}", 0, GITHUB_PAT, false);
        push(r"github_pat_[0-9A-Za-z_]{60,}", 0, GITHUB_PAT, false);
        push(r#""type"\s*:\s*"service_account""#, 0, GCP_SA, false);
        push(r"AIza[0-9A-Za-z\-_]{35}", 0, GOOGLE_API, false);
        push(r"xox[baprs]-[0-9A-Za-z-]{10,}", 0, SLACK, false);
        push(r"sk_live_[0-9A-Za-z]{24,}", 0, STRIPE, false);
        push(r"npm_[0-9A-Za-z]{36}", 0, NPM, false);
        push(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", 0, JWT, false);
        // generic: KEY = "value"
        push(
            r#"(?i)(password|passwd|secret|api[_-]?key|access[_-]?key|secret[_-]?key|auth[_-]?token|client[_-]?secret|token)\s*[:=]\s*["']?([A-Za-z0-9_\-\.\+/=]{8,})["']?"#,
            2,
            GENERIC,
            true,
        );
        v
    })
}

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    let mut n = 0usize;
    for b in s.bytes() {
        counts[b as usize] += 1;
        n += 1;
    }
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / n as f64;
            h -= p * p.log2();
        }
    }
    h
}

fn placeholderish(v: &str) -> bool {
    let lv = v.to_ascii_lowercase();
    if v.contains("${") || v.starts_with("$(") || v.starts_with("var.") || v.starts_with("env.") {
        return true;
    }
    const MARKERS: &[&str] = &[
        "example",
        "changeme",
        "change_me",
        "placeholder",
        "your_",
        "your-",
        "yourname",
        "dummy",
        "redacted",
        "xxxxx",
        "<",
        "secrets.",
        "vault:",
        "{{",
        "test",
        "sample",
        "todo",
        "fixme",
        "password",
        "123456",
        "********",
    ];
    MARKERS.iter().any(|m| lv.contains(m)) || v.chars().all(|c| c == '*' || c == 'x' || c == 'X')
}

fn mask(v: &str) -> String {
    let n = v.chars().count();
    if n <= 6 {
        return "******".to_string();
    }
    let head: String = v.chars().take(3).collect();
    let tail: String = v
        .chars()
        .rev()
        .take(2)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{}…{}({} chars)", head, tail, n)
}

fn line_at(content: &str, byte: usize) -> usize {
    content[..byte.min(content.len())]
        .bytes()
        .filter(|&b| b == b'\n')
        .count()
        + 1
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for rule in rules() {
        for caps in rule.re.captures_iter(content) {
            let Some(m) = caps.get(rule.grp) else {
                continue;
            };
            let val = m.as_str();
            if rule.generic {
                if placeholderish(val) || shannon_entropy(val) < 3.0 || val.len() < 10 {
                    continue;
                }
            } else if rule.pol.id == PRIVATE_KEY.id || rule.pol.id == GCP_SA.id {
                // structural markers: no placeholder filter
            } else if placeholderish(val) {
                continue;
            }
            let line = line_at(content, m.start());
            let key = format!("{}:{}:{}", rule.pol.id, line, val);
            if !seen.insert(key) {
                continue;
            }
            let observed = if rule.pol.id == PRIVATE_KEY.id {
                "PEM private key block".to_string()
            } else if rule.pol.id == GCP_SA.id {
                "service_account JSON key".to_string()
            } else {
                format!(
                    "{} = {}",
                    caps.get(1).map(|g| g.as_str()).unwrap_or("secret"),
                    mask(val)
                )
            };
            out.push(
                Finding::new(rule.pol, "secret", file)
                    .at(line)
                    .observed(observed),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_aws_key_and_private_key() {
        // Realistic-looking (non-"EXAMPLE", no "123456") key so the anti-FP filter keeps it.
        let c =
            "aws_access_key_id = AKIAZ7Q2LP4RW8TB1YC3\n-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n";
        let f = evaluate("main.tf", c);
        assert!(f.iter().any(|x| x.policy.id == AWS_KEY.id));
        assert!(f.iter().any(|x| x.policy.id == PRIVATE_KEY.id));
    }

    #[test]
    fn ignores_aws_docs_example_key() {
        // The canonical AWS docs key must NOT be reported (well-known non-secret).
        let f = evaluate("main.tf", "key = AKIAIOSFODNN7EXAMPLE\n");
        assert!(!f.iter().any(|x| x.policy.id == AWS_KEY.id));
    }

    #[test]
    fn ignores_placeholder_generic() {
        let c = "password = \"your-password-here\"\napi_key = \"${var.api_key}\"\n";
        let f = evaluate("c.yaml", c);
        assert!(!f.iter().any(|x| x.policy.id == GENERIC.id));
    }

    #[test]
    fn flags_real_generic_secret() {
        let c = "client_secret = \"a9Xk2Lp7Qz4Rw8Tb1Yc3Vd6Nf0Mg5H\"\n";
        let f = evaluate("c.tf", c);
        assert!(f.iter().any(|x| x.policy.id == GENERIC.id));
    }
}
