//! docker-compose analyzer: container-runtime hardening across services (privilege, host
//! namespaces, the Docker socket, capabilities, seccomp/apparmor, secrets, exposure, image pinning).

use super::model::{line_of, Finding, PolicyMeta, Severity};
use serde_yaml::Value;

use Severity::{Critical, High, Low, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "docker_compose", provider: "docker",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const PRIVILEGED: PolicyMeta = pol!("WZ-CMP-001", "Service runs in privileged mode", Critical, "A compose service sets privileged: true, granting host-equivalent root access.", "Remove privileged: true; grant only the specific cap_add the service needs.", "T1610", "CWE-250", &["CIS-Docker-5.4"], &["CIS-Docker-5.4", "NIST-AC-6", "MITRE-T1610"]);
pub const DOCKER_SOCK: PolicyMeta = pol!("WZ-CMP-002", "Docker socket mounted into a container", Critical, "A service mounts /var/run/docker.sock, which is equivalent to giving the container root on the host.", "Do not mount the Docker socket; use a scoped API proxy or rootless tooling if container control is required.", "T1610", "CWE-668", &["CIS-Docker-5.31"], &["CIS-Docker-5.31", "NIST-AC-6", "MITRE-T1610"]);
pub const HOST_NETWORK: PolicyMeta = pol!("WZ-CMP-003", "Service uses host network mode", High, "network_mode: host shares the host network stack, bypassing isolation and exposing host interfaces.", "Use the default bridge network and publish only required ports.", "T1610", "CWE-668", &["CIS-Docker-5.29"], &["CIS-Docker-5.29", "NIST-SC-7"]);
pub const HOST_PID: PolicyMeta = pol!("WZ-CMP-004", "Service uses host PID namespace", High, "pid: host lets the container view and signal host processes.", "Remove pid: host.", "T1610", "CWE-668", &["CIS-Docker-5.15"], &["CIS-Docker-5.15", "NIST-AC-6"]);
pub const CAP_ADD: PolicyMeta = pol!("WZ-CMP-005", "Service adds dangerous capabilities", High, "cap_add grants powerful capabilities (SYS_ADMIN, NET_ADMIN, ALL, …) enabling escape.", "Use cap_drop: [ALL] and add back only the minimal capability set.", "T1610", "CWE-250", &["CIS-Docker-5.3"], &["CIS-Docker-5.3", "NIST-AC-6"]);
pub const SECCOMP_OFF: PolicyMeta = pol!("WZ-CMP-006", "seccomp/apparmor confinement disabled", High, "security_opt disables seccomp or AppArmor (unconfined), removing syscall filtering.", "Remove the unconfined option; keep the default seccomp/apparmor profiles or a custom hardened one.", "T1610", "CWE-693", &["CIS-Docker-5.21"], &["CIS-Docker-5.21", "NIST-SC-7"]);
pub const SECRET_ENV: PolicyMeta = pol!("WZ-CMP-007", "Secret hard-coded in environment", High, "A service's environment embeds a credential in plaintext in the compose file.", "Use the `secrets:` mechanism or inject via a non-committed .env / secret manager.", "T1552.001", "CWE-798", &["CIS-Docker-x"], &["NIST-IA-5", "PCI-DSS-8.2.1", "MITRE-T1552.001"]);
pub const LATEST: PolicyMeta = pol!("WZ-CMP-008", "Service image uses a mutable tag", Low, "A service image uses 'latest' or no tag.", "Pin to an immutable digest or fixed version tag.", "T1525", "CWE-494", &["CIS-Docker-x"], &["NIST-CM-2"]);
pub const EXPOSE_ALL: PolicyMeta = pol!("WZ-CMP-009", "Port published on all host interfaces", Medium, "A published port has no host IP (or uses 0.0.0.0), exposing it on every interface including public ones.", "Bind to a specific interface (e.g. 127.0.0.1:PORT:PORT) and use a reverse proxy/firewall.", "T1190", "CWE-668", &["CIS-Docker-x"], &["NIST-SC-7"]);
pub const NO_READONLY: PolicyMeta = pol!("WZ-CMP-010", "Container filesystem is writable", Low, "read_only is not true, allowing tampering/persistence inside the container.", "Set read_only: true and mount tmpfs/volumes for writable paths.", "T1222", "CWE-732", &["CIS-Docker-5.12"], &["NIST-CM-5"]);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![PRIVILEGED, DOCKER_SOCK, HOST_NETWORK, HOST_PID, CAP_ADD, SECCOMP_OFF, SECRET_ENV, LATEST, EXPOSE_ALL, NO_READONLY]
}

fn as_strings(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Sequence(seq) => seq.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
        _ => vec![],
    }
}

fn secretish(s: &str) -> bool {
    let up = s.to_ascii_uppercase();
    const KEYS: &[&str] = &["PASSWORD", "PASSWD", "SECRET", "API_KEY", "APIKEY", "ACCESS_KEY", "SECRET_KEY", "TOKEN", "PRIVATE_KEY"];
    KEYS.iter().any(|k| up.contains(k))
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(doc): Result<Value, _> = serde_yaml::from_str(content) else { return out };
    let Some(services) = doc.get("services").and_then(Value::as_mapping) else { return out };

    for (name_v, svc) in services {
        let name = name_v.as_str().unwrap_or("service").to_string();
        let line = line_of(content, &format!("{}:", name)).max(1);

        if svc.get("privileged").and_then(Value::as_bool) == Some(true) {
            out.push(Finding::new(PRIVILEGED, &name, file).at(line).observed("privileged: true").fix("# remove privileged; use cap_add for specific needs"));
        }
        if let Some(nm) = svc.get("network_mode").and_then(Value::as_str) {
            if nm == "host" {
                out.push(Finding::new(HOST_NETWORK, &name, file).at(line).observed("network_mode: host"));
            }
        }
        if svc.get("pid").and_then(Value::as_str) == Some("host") {
            out.push(Finding::new(HOST_PID, &name, file).at(line).observed("pid: host"));
        }
        if svc.get("read_only").and_then(Value::as_bool) != Some(true) {
            out.push(Finding::new(NO_READONLY, &name, file).at(line).observed("read_only not true").fix("read_only: true"));
        }

        // capabilities
        if let Some(caps) = svc.get("cap_add") {
            let add: Vec<String> = as_strings(caps).iter().map(|s| s.to_ascii_uppercase()).collect();
            const DANGER: &[&str] = &["ALL", "SYS_ADMIN", "NET_ADMIN", "NET_RAW", "SYS_PTRACE", "SYS_MODULE", "DAC_OVERRIDE"];
            if add.iter().any(|a| DANGER.contains(&a.as_str())) {
                out.push(Finding::new(CAP_ADD, &name, file).at(line).observed(format!("cap_add: {:?}", add)).fix("cap_drop: [ALL]"));
            }
        }

        // security_opt unconfined
        if let Some(opts) = svc.get("security_opt") {
            for o in as_strings(opts) {
                let lo = o.to_ascii_lowercase();
                if lo.contains("unconfined") || lo.contains("seccomp=unconfined") || lo.contains("apparmor=unconfined") {
                    out.push(Finding::new(SECCOMP_OFF, &name, file).at(line).observed(format!("security_opt: {}", o)));
                }
            }
        }

        // volumes — docker socket
        if let Some(vols) = svc.get("volumes") {
            let entries = match vols {
                Value::Sequence(seq) => seq.clone(),
                _ => vec![],
            };
            for v in &entries {
                let s = match v {
                    Value::String(s) => s.clone(),
                    Value::Mapping(_) => v.get("source").and_then(Value::as_str).unwrap_or("").to_string(),
                    _ => String::new(),
                };
                if s.contains("docker.sock") {
                    out.push(Finding::new(DOCKER_SOCK, &name, file).at(line).observed(format!("volume: {}", s)));
                }
            }
        }

        // environment secrets
        match svc.get("environment") {
            Some(Value::Sequence(seq)) => {
                for e in seq {
                    if let Some(s) = e.as_str() {
                        if secretish(s) && s.contains('=') {
                            let val = s.splitn(2, '=').nth(1).unwrap_or("").trim();
                            if !val.is_empty() && !val.starts_with('$') {
                                out.push(Finding::new(SECRET_ENV, &name, file).at(line).observed(super::model::truncate(s, 100)));
                            }
                        }
                    }
                }
            }
            Some(Value::Mapping(m)) => {
                for (k, val) in m {
                    let key = k.as_str().unwrap_or("");
                    let valstr = val.as_str().unwrap_or("");
                    if secretish(key) && !valstr.is_empty() && !valstr.starts_with('$') {
                        out.push(Finding::new(SECRET_ENV, &name, file).at(line).observed(format!("{}={}", key, super::model::truncate(valstr, 40))));
                    }
                }
            }
            _ => {}
        }

        // image tag
        if let Some(image) = svc.get("image").and_then(Value::as_str) {
            let tag = image.rsplit(':').next().unwrap_or("");
            let has_tag = image.contains(':') && tag != image && !image.contains('@');
            if (!has_tag && !image.contains('@')) || tag == "latest" {
                out.push(Finding::new(LATEST, &name, file).at(line).observed(format!("image: {}", image)));
            }
        }

        // exposed ports
        if let Some(Value::Sequence(ports)) = svc.get("ports") {
            for p in ports {
                let s = match p {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Mapping(_) => p.get("published").map(|v| v.as_str().map(str::to_string).unwrap_or_else(|| v.as_u64().map(|n| n.to_string()).unwrap_or_default())).unwrap_or_default(),
                    _ => String::new(),
                };
                if s.is_empty() {
                    continue;
                }
                // "127.0.0.1:8080:80" is fine; "8080:80" or "0.0.0.0:8080:80" is all-interfaces
                let bound_specific = s.contains(':') && !s.starts_with("0.0.0.0:") && s.matches(':').count() >= 2;
                if !bound_specific {
                    out.push(Finding::new(EXPOSE_ALL, &name, file).at(line).observed(format!("ports: {}", s)).fix(format!("\"127.0.0.1:{}\"", s)));
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
    fn flags_socket_and_privileged() {
        let y = r#"
services:
  app:
    image: nginx:latest
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"#;
        let f = evaluate("docker-compose.yml", y);
        assert!(f.iter().any(|x| x.policy.id == PRIVILEGED.id));
        assert!(f.iter().any(|x| x.policy.id == DOCKER_SOCK.id));
        assert!(f.iter().any(|x| x.policy.id == LATEST.id));
    }
}
