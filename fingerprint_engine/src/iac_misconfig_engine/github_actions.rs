//! GitHub Actions workflow analyzer: CI/CD supply-chain controls (pwn-request, untrusted script
//! injection, unpinned actions, over-broad permissions, hard-coded secrets, self-hosted exposure).

use super::model::{line_of, Finding, PolicyMeta, Severity};
use serde_yaml::Value;

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "github_actions",
            provider: "github",
            description: $desc,
            remediation: $rem,
            mitre: $mitre,
            cwe: $cwe,
            references: $refs,
            compliance: $comp,
        }
    };
}

pub const PWN_REQUEST: PolicyMeta = pol!("WZ-GHA-001", "pull_request_target checks out untrusted PR code", Critical, "A workflow triggered by pull_request_target checks out the PR head ref while running with repository secrets — the classic 'pwn request' enabling secret exfiltration and code execution.", "Avoid building/executing PR code under pull_request_target. If needed, use pull_request, or checkout the base ref and never run untrusted code with secrets.", "T1195.002", "CWE-829", &["https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"], &["NIST-SA-12", "PCI-DSS-6.3.2", "MITRE-T1195.002"]);
pub const SCRIPT_INJECTION: PolicyMeta = pol!("WZ-GHA-002", "Untrusted input used in run step (script injection)", High, "A run step interpolates attacker-controllable ${{ github.event.* }} / head_ref data directly into a shell, enabling command injection on the runner.", "Pass untrusted values via env: and reference them as quoted \"$VAR\"; never inline ${{ github.event.* }} into run scripts.", "T1059", "CWE-94", &["https://securitylab.github.com/research/github-actions-untrusted-input/"], &["NIST-SI-10", "PCI-DSS-6.5.1", "MITRE-T1059"]);
pub const UNPINNED_BRANCH: PolicyMeta = pol!("WZ-GHA-003", "Action pinned to a mutable branch", High, "A `uses:` references a third-party action by branch (e.g. @main/@master), so a maintainer or attacker can change the executed code at any time.", "Pin third-party actions to a full commit SHA (uses: org/action@<40-char-sha>).", "T1195.001", "CWE-494", &["https://docs.github.com/actions/security-guides/security-hardening-for-github-actions"], &["NIST-SA-12", "SOC2-CC8.1", "MITRE-T1195.001"]);
pub const UNPINNED_TAG: PolicyMeta = pol!("WZ-GHA-004", "Action pinned to a tag, not a SHA", Medium, "A `uses:` references a third-party action by tag (e.g. @v4); tags are mutable and can be re-pointed to malicious code.", "Pin third-party actions to a full commit SHA for immutability.", "T1195.001", "CWE-494", &["https://docs.github.com/actions/security-guides/security-hardening-for-github-actions"], &["NIST-SA-12", "SOC2-CC8.1"]);
pub const WRITE_ALL: PolicyMeta = pol!("WZ-GHA-005", "Workflow grants write-all permissions", Medium, "permissions: write-all (or an unset top-level permissions with the default read/write token) grants the GITHUB_TOKEN broad write scope.", "Set least-privilege permissions: at workflow and job level (default to contents: read).", "T1098", "CWE-269", &["https://docs.github.com/actions/security-guides/automatic-token-authentication"], &["NIST-AC-6", "SOC2-CC6.3"]);
pub const HARDCODED_SECRET: PolicyMeta = pol!("WZ-GHA-006", "Hard-coded secret in workflow env", High, "An env value embeds a credential literally instead of referencing ${{ secrets.* }}.", "Move the value into encrypted repository/organization secrets and reference ${{ secrets.NAME }}.", "T1552.001", "CWE-798", &["https://docs.github.com/actions/security-guides/encrypted-secrets"], &["NIST-IA-5", "PCI-DSS-8.2.1", "MITRE-T1552.001"]);
pub const SELF_HOSTED_PR: PolicyMeta = pol!("WZ-GHA-007", "Self-hosted runner exposed to fork PRs", High, "A workflow triggered by pull_request(_target) runs on a self-hosted runner, letting untrusted forks execute code on your infrastructure.", "Use ephemeral GitHub-hosted runners for fork PRs, or gate self-hosted jobs behind required approval.", "T1195.002", "CWE-829", &["https://docs.github.com/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security"], &["NIST-SA-12", "MITRE-T1195.002"]);
pub const CURL_PIPE: PolicyMeta = pol!(
    "WZ-GHA-008",
    "Remote script piped to shell in a step",
    High,
    "A run step pipes curl/wget output into sh/bash, executing unverified remote code in CI.",
    "Download, verify a checksum/signature, then execute.",
    "T1195.002",
    "CWE-494",
    &["https://owasp.org/www-project-devsecops-guideline/"],
    &["NIST-SA-12", "PCI-DSS-6.3.2"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![
        PWN_REQUEST,
        SCRIPT_INJECTION,
        UNPINNED_BRANCH,
        UNPINNED_TAG,
        WRITE_ALL,
        HARDCODED_SECRET,
        SELF_HOSTED_PR,
        CURL_PIPE,
    ]
}

/// Workflow triggers, robust to a YAML parser coercing the `on:` key to boolean `true`.
fn triggers(doc: &Value) -> Vec<String> {
    let Some(m) = doc.as_mapping() else {
        return vec![];
    };
    let mut on_val: Option<&Value> = None;
    for (k, v) in m {
        match k {
            Value::String(s) if s == "on" => on_val = Some(v),
            Value::Bool(true) if on_val.is_none() => on_val = Some(v),
            _ => {}
        }
    }
    match on_val {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Sequence(seq)) => seq
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        Some(Value::Mapping(mm)) => mm
            .iter()
            .filter_map(|(k, _)| k.as_str().map(str::to_string))
            .collect(),
        _ => vec![],
    }
}

fn secretish(s: &str) -> bool {
    let up = s.to_ascii_uppercase();
    const KEYS: &[&str] = &[
        "PASSWORD",
        "SECRET",
        "API_KEY",
        "APIKEY",
        "ACCESS_KEY",
        "SECRET_KEY",
        "TOKEN",
        "PRIVATE_KEY",
        "NPM_TOKEN",
        "AWS_SECRET",
    ];
    KEYS.iter().any(|k| up.contains(k))
}

fn dangerous_context(run: &str) -> bool {
    let r = run;
    const PATTERNS: &[&str] = &[
        "${{ github.event.issue.title",
        "${{ github.event.issue.body",
        "${{ github.event.pull_request.title",
        "${{ github.event.pull_request.body",
        "${{ github.event.pull_request.head.ref",
        "${{ github.event.comment.body",
        "${{ github.event.review.body",
        "${{ github.event.review_comment.body",
        "${{ github.event.pages",
        "${{ github.event.head_commit.message",
        "${{ github.head_ref",
        "${{ github.event.discussion.title",
        "${{ github.event.discussion.body",
    ];
    let compact = r.replace("${{github", "${{ github");
    PATTERNS.iter().any(|p| compact.contains(p))
}

fn env_secrets(
    file: &str,
    content: &str,
    env: Option<&Value>,
    scope: &str,
    line: usize,
    out: &mut Vec<Finding>,
) {
    if let Some(Value::Mapping(m)) = env {
        for (k, v) in m {
            let key = k.as_str().unwrap_or("");
            let val = v.as_str().unwrap_or("");
            if secretish(key) && !val.is_empty() && !val.contains("${{") {
                out.push(
                    Finding::new(HARDCODED_SECRET, scope, file)
                        .at(line_of(content, key).max(line))
                        .observed(format!("{}: {}", key, super::model::truncate(val, 40)))
                        .fix(format!("{}: ${{{{ secrets.{} }}}}", key, key)),
                );
            }
        }
    }
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(doc): Result<Value, _> = serde_yaml::from_str(content) else {
        return out;
    };
    if !doc.is_mapping() {
        return out;
    }
    let trigs = triggers(&doc);
    let has_pr_target = trigs.iter().any(|t| t == "pull_request_target");
    let has_pr = trigs
        .iter()
        .any(|t| t == "pull_request" || t == "pull_request_target");

    // top-level permissions
    if doc.get("permissions").and_then(Value::as_str) == Some("write-all") {
        out.push(
            Finding::new(WRITE_ALL, "workflow", file)
                .at(line_of(content, "permissions").max(1))
                .observed("permissions: write-all")
                .fix("permissions:\n  contents: read"),
        );
    }
    env_secrets(file, content, doc.get("env"), "workflow", 1, &mut out);

    let Some(jobs) = doc.get("jobs").and_then(Value::as_mapping) else {
        return out;
    };
    for (jn, job) in jobs {
        let jname = jn.as_str().unwrap_or("job").to_string();
        let jline = line_of(content, &format!("{}:", jname)).max(1);

        if job.get("permissions").and_then(Value::as_str) == Some("write-all") {
            out.push(
                Finding::new(WRITE_ALL, &jname, file)
                    .at(jline)
                    .observed("permissions: write-all")
                    .fix("permissions:\n  contents: read"),
            );
        }
        env_secrets(file, content, job.get("env"), &jname, jline, &mut out);

        // self-hosted runner on PR triggers
        let runs_on = job.get("runs-on");
        let self_hosted = match runs_on {
            Some(Value::String(s)) => s.contains("self-hosted"),
            Some(Value::Sequence(seq)) => seq.iter().any(|x| {
                x.as_str()
                    .map(|s| s.contains("self-hosted"))
                    .unwrap_or(false)
            }),
            _ => false,
        };
        if self_hosted && has_pr {
            out.push(
                Finding::new(SELF_HOSTED_PR, &jname, file)
                    .at(jline)
                    .observed("runs-on: self-hosted with pull_request trigger"),
            );
        }

        let Some(steps) = job.get("steps").and_then(Value::as_sequence) else {
            continue;
        };
        for step in steps {
            let sline = step
                .get("name")
                .and_then(Value::as_str)
                .map(|n| line_of(content, n))
                .filter(|l| *l > 0)
                .unwrap_or(jline);
            env_secrets(file, content, step.get("env"), &jname, sline, &mut out);

            // uses: pinning
            if let Some(uses) = step.get("uses").and_then(Value::as_str) {
                if !uses.starts_with("./") && !uses.starts_with("docker://") && uses.contains('@') {
                    let reff = uses.rsplit('@').next().unwrap_or("");
                    let is_sha = reff.len() == 40 && reff.chars().all(|c| c.is_ascii_hexdigit());
                    if !is_sha {
                        if reff == "main"
                            || reff == "master"
                            || (!reff.starts_with('v')
                                && !reff
                                    .chars()
                                    .next()
                                    .map(|c| c.is_ascii_digit())
                                    .unwrap_or(false))
                        {
                            out.push(
                                Finding::new(UNPINNED_BRANCH, &jname, file)
                                    .at(sline)
                                    .observed(format!("uses: {}", uses))
                                    .fix(format!(
                                        "uses: {}@<40-char-commit-sha>",
                                        uses.split('@').next().unwrap_or(uses)
                                    )),
                            );
                        } else {
                            out.push(
                                Finding::new(UNPINNED_TAG, &jname, file)
                                    .at(sline)
                                    .observed(format!("uses: {}", uses))
                                    .fix(format!(
                                        "uses: {}@<40-char-commit-sha>",
                                        uses.split('@').next().unwrap_or(uses)
                                    )),
                            );
                        }
                    }
                }
                // pwn-request: pull_request_target + checkout of PR head ref
                if has_pr_target && uses.contains("actions/checkout") {
                    let reff = step
                        .get("with")
                        .and_then(|w| w.get("ref"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if reff.contains("head.ref")
                        || reff.contains("head.sha")
                        || reff.contains("github.event.pull_request")
                    {
                        out.push(
                            Finding::new(PWN_REQUEST, &jname, file)
                                .at(sline)
                                .observed(format!("checkout ref: {}", reff)),
                        );
                    }
                }
            }

            // run: script injection + curl|sh
            if let Some(run) = step.get("run").and_then(Value::as_str) {
                if dangerous_context(run) {
                    out.push(Finding::new(SCRIPT_INJECTION, &jname, file).at(sline).observed(super::model::truncate(run, 160)).fix("env:\n  DATA: ${{ github.event.issue.title }}\nrun: echo \"$DATA\""));
                }
                let rl = run.to_ascii_lowercase();
                if (rl.contains("curl") || rl.contains("wget"))
                    && (rl.contains("| sh")
                        || rl.contains("|sh")
                        || rl.contains("| bash")
                        || rl.contains("|bash"))
                {
                    out.push(
                        Finding::new(CURL_PIPE, &jname, file)
                            .at(sline)
                            .observed(super::model::truncate(run, 160)),
                    );
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_pwn_request_and_injection() {
        let y = r#"
on: pull_request_target
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
        with:
          ref: ${{ github.event.pull_request.head.ref }}
      - run: echo "${{ github.event.issue.title }}"
"#;
        let f = evaluate(".github/workflows/ci.yml", y);
        assert!(
            f.iter().any(|x| x.policy.id == PWN_REQUEST.id),
            "pwn request"
        );
        assert!(
            f.iter().any(|x| x.policy.id == SCRIPT_INJECTION.id),
            "script injection"
        );
        assert!(
            f.iter().any(|x| x.policy.id == UNPINNED_BRANCH.id),
            "unpinned"
        );
        assert!(f.iter().any(|x| x.policy.id == WRITE_ALL.id), "write-all");
    }
}
