//! Ansible playbook / role analyzer — risky task modules, world-writable file modes, unconstrained
//! privilege escalation, and cleartext credentials in vars.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "ansible", provider: "generic",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const SHELL_RAW: PolicyMeta = pol!("WZ-ANS-001", "Ansible uses raw shell/command without guardrails", High, "Tasks invoke ansible.builtin.shell or command, bypassing idempotency and hiding malicious command injection.", "Use dedicated modules (package, file, template) or wrap shell in scripts with checksum verification.", "T1059", "CWE-78", &["CIS-Ansible"], &["NIST-CM-2", "SOC2-CC8.1"]);
pub const WORLD_WRITABLE: PolicyMeta = pol!("WZ-ANS-002", "Ansible sets file mode world-writable (0777)", High, "copy/template/file tasks set mode 0777 or 'a+rwx', allowing any user to tamper with deployed artifacts.", "Use mode '0644' for files and '0755' for directories; never 0777.", "T1222", "CWE-732", &["CIS-Ansible"], &["NIST-AC-6", "PCI-DSS-2.2.4"]);
pub const BECOME_ALL: PolicyMeta = pol!("WZ-ANS-003", "Playbook escalates privileges globally (become: yes)", Medium, "become: true at play level runs every task as root without scoped become_user.", "Scope become to specific tasks; use become_user with least privilege.", "T1548", "CWE-269", &["CIS-Ansible"], &["NIST-AC-6", "SOC2-CC6.3"]);
pub const VARS_SECRET: PolicyMeta = pol!("WZ-ANS-004", "Cleartext secret in Ansible vars", Critical, "vars/defaults contain password/token/api_key literals committed to VCS.", "Use Ansible Vault (ansible-vault encrypt) or external secret managers.", "T1552.001", "CWE-798", &["CIS-Ansible"], &["NIST-IA-5", "PCI-DSS-8.2.1", "MITRE-T1552.001"]);
pub const VAULT_PLAINTEXT: PolicyMeta = pol!("WZ-ANS-005", "Ansible secret var not Vault-encrypted", High, "Sensitive variable present without $ANSIBLE_VAULT; prefix or vault-encrypted file block.", "Encrypt with ansible-vault encrypt_string or move to HashiCorp Vault / AWX credentials.", "T1552.001", "CWE-312", &["CIS-Ansible"], &["NIST-IA-5", "PCI-DSS-8.2.1"]);
pub const NOPASSWD: PolicyMeta = pol!("WZ-ANS-006", "Ansible configures passwordless sudo (NOPASSWD)", High, "lineinfile/copy task writes NOPASSWD to sudoers — any compromised user gains root.", "Require password for sudo; use become with scoped become_user and sudo -l restrictions.", "T1548", "CWE-269", &["CIS-Ansible"], &["NIST-AC-6", "SOC2-CC6.3"]);
pub const UNSAFE_URI: PolicyMeta = pol!("WZ-ANS-007", "Ansible downloads from remote URI without checksum", High, "get_url / uri module fetches remote content without checksum or TLS validation.", "Pin checksums; set validate_certs: true; use internal artifact registry.", "T1195.002", "CWE-494", &["CIS-Ansible"], &["NIST-SA-12", "SOC2-CC8.1"]);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![SHELL_RAW, WORLD_WRITABLE, BECOME_ALL, VARS_SECRET, VAULT_PLAINTEXT, NOPASSWD, UNSAFE_URI]
}

fn is_ansible(name: &str, content: &str) -> bool {
    let n = name.to_ascii_lowercase();
    (n.ends_with(".yml") || n.ends_with(".yaml"))
        && (n.contains("playbook") || n.contains("/roles/") || n.ends_with("main.yml") || content.contains("- hosts:") || content.contains("- name:"))
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_ansible(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("ansible.builtin.shell") || lc.contains("ansible.builtin.command") || lc.contains("shell:") || lc.contains("command:") {
        if !lc.contains("changed_when:") && !lc.contains("creates:") && !lc.contains("removes:") {
            out.push(Finding::new(SHELL_RAW, file, file).observed("shell/command task without changed_when/creates"));
        }
    }
    if lc.contains("mode: '0777'") || lc.contains("mode: 0777") || lc.contains("mode: \"0777\"") {
        out.push(Finding::new(WORLD_WRITABLE, file, file).observed("mode 0777"));
    }
    if (lc.contains("become: true") || lc.contains("become: yes")) && !lc.contains("become_user:") {
        out.push(Finding::new(BECOME_ALL, file, file).observed("become without become_user"));
    }
    for key in ["password:", "api_key:", "secret:", "token:", "private_key:"] {
        if lc.contains(key) {
            let lines: Vec<&str> = content.lines().collect();
            for line in lines {
                let ll = line.to_ascii_lowercase();
                if ll.contains(key) && !ll.contains("vault") && !ll.contains("{{") && line.contains(':') {
                    let val = line.split(':').nth(1).unwrap_or("").trim();
                    if !val.is_empty() && val != "\"\"" && val != "''" {
                        if !content.contains("$ANSIBLE_VAULT;") {
                            out.push(Finding::new(VAULT_PLAINTEXT, file, file).observed(format!("{key} without vault encryption")));
                        }
                        out.push(Finding::new(VARS_SECRET, file, file).observed(format!("{key} cleartext in vars")));
                        break;
                    }
                }
            }
        }
    }
    if lc.contains("nopasswd") && (lc.contains("sudoers") || lc.contains("lineinfile") || lc.contains("/etc/sudoers")) {
        out.push(Finding::new(NOPASSWD, file, file).observed("NOPASSWD in sudoers task"));
    }
    if (lc.contains("get_url:") || lc.contains("ansible.builtin.get_url")) && !lc.contains("checksum:") && !lc.contains("validate_certs: true") {
        out.push(Finding::new(UNSAFE_URI, file, file).observed("remote URI fetch without checksum/TLS validation"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_world_writable() {
        let y = "- hosts: all\n  tasks:\n    - copy:\n        dest: /app\n        mode: '0777'\n";
        assert!(evaluate("playbook.yml", y).iter().any(|f| f.policy.id == WORLD_WRITABLE.id));
    }
}
