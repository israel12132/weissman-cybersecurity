//! Dockerfile analyzer: CIS Docker Benchmark + common container build hardening checks. Line-based
//! (handling line continuations) so it works on any Dockerfile without a full grammar.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{High, Low, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "dockerfile", provider: "docker",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const RUNS_AS_ROOT: PolicyMeta = pol!("WZ-DKR-001", "Image runs as root (no USER set)", Medium, "The final build stage has no non-root USER instruction (or sets USER root/0), so the container runs as root.", "Add a non-root USER (e.g. create an app user and `USER 10001`) before CMD/ENTRYPOINT.", "T1611", "CWE-250", &["CIS-Docker-4.1"], &["CIS-Docker-4.1", "NIST-AC-6", "PCI-DSS-2.2.4"]);
pub const LATEST_TAG: PolicyMeta = pol!("WZ-DKR-002", "Base image uses 'latest' or no tag", Low, "FROM references an image without a pinned version/digest, making builds non-reproducible.", "Pin the base image to a digest (FROM image@sha256:…) or a fixed version tag.", "T1525", "CWE-494", &["CIS-Docker-4.7"], &["NIST-CM-2", "SOC2-CC8.1"]);
pub const ADD_REMOTE: PolicyMeta = pol!("WZ-DKR-003", "ADD fetches a remote URL", Medium, "ADD with a remote URL silently downloads and can auto-extract archives, hiding supply-chain risk.", "Use COPY for local files; for remote fetches use RUN curl with checksum verification.", "T1195", "CWE-494", &["CIS-Docker-4.x"], &["NIST-SA-12", "SOC2-CC8.1"]);
pub const CURL_PIPE_SH: PolicyMeta = pol!("WZ-DKR-004", "Remote script piped directly into a shell", High, "A RUN instruction pipes curl/wget output straight into sh/bash, executing unverified remote code at build time.", "Download to a file, verify a checksum/signature, then execute. Never pipe network output to a shell.", "T1195.002", "CWE-494", &["https://owasp.org/www-project-devsecops-guideline/"], &["NIST-SA-12", "PCI-DSS-6.3.2", "MITRE-T1195.002"]);
pub const HARDCODED_SECRET: PolicyMeta = pol!("WZ-DKR-005", "Secret hard-coded in ENV/ARG", High, "An ENV or ARG instruction embeds a credential, which is baked into image layers and leaks via `docker history`.", "Pass secrets at runtime (Docker secrets / env at deploy) or use BuildKit --secret mounts; never bake them in.", "T1552.001", "CWE-798", &["CIS-Docker-4.10"], &["CIS-Docker-4.10", "NIST-IA-5", "PCI-DSS-8.2.1", "MITRE-T1552.001"]);
pub const COPY_SSH_KEY: PolicyMeta = pol!("WZ-DKR-006", "Private key / SSH material copied into image", High, "COPY/ADD brings a private key or .ssh directory into the image, exposing it in layers.", "Never copy private keys into an image; use BuildKit secret mounts or runtime injection.", "T1552.004", "CWE-798", &["CIS-Docker-4.x"], &["NIST-IA-5", "PCI-DSS-8.2.1"]);
pub const CHMOD_777: PolicyMeta = pol!("WZ-DKR-007", "World-writable permissions (chmod 777)", Medium, "A RUN sets 0777 permissions, allowing any user/process to modify files (tamper, persistence).", "Use least-privilege permissions (e.g. 0755 for dirs, 0644 for files) and a dedicated owner.", "T1222", "CWE-732", &["CIS-Docker-4.x"], &["NIST-AC-6", "SOC2-CC6.8"]);
pub const HTTP_DOWNLOAD: PolicyMeta = pol!("WZ-DKR-008", "Build downloads over cleartext HTTP", Medium, "A RUN fetches resources over http://, which is susceptible to MITM tampering.", "Use https:// for all downloads and verify checksums/signatures.", "T1195", "CWE-319", &["CIS-Docker-4.x"], &["NIST-SC-8", "SOC2-CC8.1"]);
pub const SUDO_INSTALL: PolicyMeta = pol!("WZ-DKR-009", "sudo installed in image", Low, "Installing sudo in a container image enables privilege escalation paths.", "Remove sudo; run the process as the required user directly or use USER.", "T1548", "CWE-250", &["CIS-Docker-4.x"], &["NIST-AC-6"]);
pub const APT_NO_VERIFY: PolicyMeta = pol!("WZ-DKR-010", "Package manager certificate/GPG check disabled", High, "A RUN disables TLS or GPG verification (e.g. --allow-unauthenticated, --no-check-certificate, pip --trusted-host).", "Re-enable verification; never bypass package signing/TLS checks in builds.", "T1195.002", "CWE-494", &["CIS-Docker-4.x"], &["NIST-SA-12", "PCI-DSS-6.3.2"]);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![RUNS_AS_ROOT, LATEST_TAG, ADD_REMOTE, CURL_PIPE_SH, HARDCODED_SECRET, COPY_SSH_KEY, CHMOD_777, HTTP_DOWNLOAD, SUDO_INSTALL, APT_NO_VERIFY]
}

/// Logical (continuation-joined) instructions with their starting line number.
fn instructions(content: &str) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut start_line = 0usize;
    for (idx, raw) in content.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw.trim_end();
        let no_comment = {
            let t = trimmed.trim_start();
            if t.starts_with('#') {
                continue;
            }
            trimmed
        };
        if buf.is_empty() {
            start_line = line_no;
        }
        if let Some(stripped) = no_comment.strip_suffix('\\') {
            buf.push_str(stripped);
            buf.push(' ');
        } else {
            buf.push_str(no_comment);
            if !buf.trim().is_empty() {
                out.push((buf.trim().to_string(), start_line));
            }
            buf.clear();
        }
    }
    if !buf.trim().is_empty() {
        out.push((buf.trim().to_string(), start_line));
    }
    out
}

fn secretish(s: &str) -> bool {
    let up = s.to_ascii_uppercase();
    const KEYS: &[&str] = &["PASSWORD", "PASSWD", "SECRET", "API_KEY", "APIKEY", "ACCESS_KEY", "SECRET_KEY", "TOKEN", "PRIVATE_KEY", "AWS_SECRET"];
    KEYS.iter().any(|k| up.contains(k))
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut final_user: Option<String> = None;
    let mut user_line = 0usize;
    let mut last_from_line = 0usize;

    for (ins, line) in instructions(content) {
        let mut parts = ins.splitn(2, char::is_whitespace);
        let verb = parts.next().unwrap_or("").to_ascii_uppercase();
        let rest = parts.next().unwrap_or("").trim().to_string();
        let rest_l = rest.to_ascii_lowercase();
        match verb.as_str() {
            "FROM" => {
                final_user = None; // each stage resets the runtime user
                last_from_line = line;
                let image = rest.split_whitespace().next().unwrap_or("");
                let image = image.split(" AS ").next().unwrap_or(image);
                if !image.is_empty() && !image.contains('@') && !image.starts_with("$") {
                    let tag = image.rsplit(':').next().unwrap_or("");
                    let has_tag = image.contains(':') && tag != image;
                    if !has_tag || tag == "latest" {
                        out.push(Finding::new(LATEST_TAG, image, file).at(line).observed(format!("FROM {}", image)).fix(format!("FROM {}@sha256:<digest>", image.split(':').next().unwrap_or(image))));
                    }
                }
            }
            "USER" => {
                final_user = Some(rest.clone());
                user_line = line;
            }
            "ENV" | "ARG" => {
                if secretish(&rest) && rest.contains('=') {
                    // skip pure references like ENV FOO=$BAR
                    let val = rest.splitn(2, '=').nth(1).unwrap_or("").trim();
                    if !val.is_empty() && !val.starts_with('$') {
                        out.push(Finding::new(HARDCODED_SECRET, "Dockerfile", file).at(line).observed(format!("{} {}", verb, super::model::truncate(&rest, 120))).fix(format!("# inject {} at runtime; do not bake into the image", verb)));
                    }
                }
            }
            "ADD" => {
                if rest_l.contains("http://") || rest_l.contains("https://") {
                    out.push(Finding::new(ADD_REMOTE, "Dockerfile", file).at(line).observed(format!("ADD {}", super::model::truncate(&rest, 120))).fix("# use COPY for local files; RUN curl + checksum for remote"));
                }
                if rest_l.contains("id_rsa") || rest_l.contains(".ssh") || rest_l.contains(".pem") {
                    out.push(Finding::new(COPY_SSH_KEY, "Dockerfile", file).at(line).observed(format!("ADD {}", super::model::truncate(&rest, 120))));
                }
            }
            "COPY" => {
                if rest_l.contains("id_rsa") || rest_l.contains(".ssh") || rest_l.contains("id_ed25519") || rest_l.contains(".pem") {
                    out.push(Finding::new(COPY_SSH_KEY, "Dockerfile", file).at(line).observed(format!("COPY {}", super::model::truncate(&rest, 120))));
                }
            }
            "RUN" => {
                let pipes_shell = (rest_l.contains("curl") || rest_l.contains("wget")) && (rest_l.contains("| sh") || rest_l.contains("|sh") || rest_l.contains("| bash") || rest_l.contains("|bash"));
                if pipes_shell {
                    out.push(Finding::new(CURL_PIPE_SH, "Dockerfile", file).at(line).observed(super::model::truncate(&rest, 160)).fix("# download to file, verify checksum/signature, then run"));
                }
                if rest_l.contains("chmod 777") || rest_l.contains("chmod -r 777") || rest_l.contains("chmod -r777") {
                    out.push(Finding::new(CHMOD_777, "Dockerfile", file).at(line).observed(super::model::truncate(&rest, 120)).fix("chmod 0755 ..."));
                }
                if rest_l.contains("http://") {
                    out.push(Finding::new(HTTP_DOWNLOAD, "Dockerfile", file).at(line).observed(super::model::truncate(&rest, 120)).fix("# use https://"));
                }
                if rest_l.contains("install") && rest_l.contains("sudo") {
                    out.push(Finding::new(SUDO_INSTALL, "Dockerfile", file).at(line).observed(super::model::truncate(&rest, 120)));
                }
                if rest_l.contains("--allow-unauthenticated") || rest_l.contains("--no-check-certificate") || rest_l.contains("--trusted-host") || rest_l.contains("apt-key adv") {
                    out.push(Finding::new(APT_NO_VERIFY, "Dockerfile", file).at(line).observed(super::model::truncate(&rest, 120)));
                }
            }
            _ => {}
        }
    }

    let runs_root = match &final_user {
        None => true,
        Some(u) => {
            let u = u.split(':').next().unwrap_or(u).trim();
            u == "root" || u == "0" || u.is_empty()
        }
    };
    if runs_root {
        let at = if user_line > 0 { user_line } else { last_from_line.max(1) };
        out.push(Finding::new(RUNS_AS_ROOT, "Dockerfile", file).at(at).observed(final_user.clone().map(|u| format!("USER {}", u)).unwrap_or_else(|| "no USER instruction".to_string())).fix("RUN useradd -u 10001 app\nUSER 10001"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_root_latest_curlpipe_secret() {
        let d = "FROM ubuntu:latest\nENV API_KEY=AKIAIOSFODNN7EXAMPLE\nRUN curl https://x.sh | bash\n";
        let f = evaluate("Dockerfile", d);
        assert!(f.iter().any(|x| x.policy.id == LATEST_TAG.id));
        assert!(f.iter().any(|x| x.policy.id == HARDCODED_SECRET.id));
        assert!(f.iter().any(|x| x.policy.id == CURL_PIPE_SH.id));
        assert!(f.iter().any(|x| x.policy.id == RUNS_AS_ROOT.id));
    }

    #[test]
    fn nonroot_pinned_is_clean_for_user_and_tag() {
        let d = "FROM ubuntu@sha256:abc\nUSER 10001\n";
        let f = evaluate("Dockerfile", d);
        assert!(!f.iter().any(|x| x.policy.id == RUNS_AS_ROOT.id));
        assert!(!f.iter().any(|x| x.policy.id == LATEST_TAG.id));
    }
}
