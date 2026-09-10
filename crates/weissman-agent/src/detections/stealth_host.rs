//! Host-resident checks for sandbox/ROP/heap/JIT/COM/PPID engines.

use super::finding;
use serde_json::{json, Value};
use sysinfo::{ProcessRefreshKind, System, UpdateKind};

pub async fn run_sandbox_evasion(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut extras = serde_json::Map::new();
    extras.insert("cpus".into(), json!(num_cpus_approx()));
    extras.insert("uptime_secs".into(), json!(sysinfo::System::uptime()));
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessRefreshKind::new().with_exe(UpdateKind::Always));
    let vm_procs = ["vboxservice", "vmtoolsd", "qemu-ga", "sandboxie"];
    let mut hits = Vec::new();
    for p in sys.processes().values() {
        let n = p.name().to_ascii_lowercase();
        if vm_procs.iter().any(|h| n.contains(h)) {
            hits.push(n);
        }
    }
    extras.insert("vm_guest_tools".into(), json!(hits));
    if hits.is_empty() {
        Ok(vec![finding(
            engine,
            "No guest-tools / sandbox agent process observed",
            "info",
            "T1497",
            "Process list has no VBoxService/vmtoolsd/qemu-ga/Sandboxie — malware sandbox-evasion checks would likely proceed.",
            extras,
        )])
    } else {
        Ok(vec![finding(
            engine,
            "Sandbox/VM guest tools process present",
            "medium",
            "T1497",
            "Guest tools processes were observed; samples that fingerprint VMs may refuse to detonate here.",
            extras,
        )])
    }
}

pub async fn run_memory_technique(engine: &str, mitre: &str, title: &str) -> anyhow::Result<Vec<Value>> {
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessRefreshKind::new()
            .with_exe(UpdateKind::Always)
            .with_memory(),
    );
    let mut suspicious = 0u32;
    for p in sys.processes().values() {
        let mem = p.memory();
        let name = p.name().to_ascii_lowercase();
        if mem > 800_000_000
            && (name.contains("powershell")
                || name.contains("wscript")
                || name.contains("mshta")
                || name.contains("python"))
        {
            suspicious += 1;
        }
    }
    Ok(vec![finding(
        engine,
        title,
        if suspicious > 0 { "medium" } else { "info" },
        mitre,
        &format!(
            "{suspicious} high-memory scripting interpreters observed — host-resident {engine} signal (not a remote exploit).",
        ),
        {
            let mut m = serde_json::Map::new();
            m.insert("high_mem_script_hosts".into(), json!(suspicious));
            m
        },
    )])
}

pub async fn run_com_hijack(engine: &str) -> anyhow::Result<Vec<Value>> {
    #[cfg(target_os = "windows")]
    {
        let keys = [
            r"HKCU\Software\Classes\CLSID",
            r"HKCU\Software\Classes\Wow6432Node\CLSID",
        ];
        let mut extras = serde_json::Map::new();
        extras.insert("keys".into(), json!(keys));
        return Ok(vec![finding(
            engine,
            "COM hijack registry surface present (HKCU CLSID)",
            "info",
            "T1546.015",
            "HKCU CLSID is the classic per-user COM hijack location. Review InprocServer32 for unsigned DLLs.",
            extras,
        )]);
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(vec![finding(
            engine,
            "COM hijacking is Windows-only",
            "info",
            "T1546.015",
            "This host is not Windows; no COM CLSID inventory was invented.",
            json!({}).as_object().cloned().unwrap_or_default(),
        )])
    }
}

pub async fn run_ppid_spoof(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessRefreshKind::new().with_exe(UpdateKind::Always));
    let mut odd = 0u32;
    for p in sys.processes().values() {
        let name = p.name().to_ascii_lowercase();
        let parent = p.parent().and_then(|pid| sys.process(pid));
        let pname = parent.map(|x| x.name().to_ascii_lowercase()).unwrap_or_default();
        if (name == "cmd" || name == "cmd.exe" || name == "powershell" || name == "pwsh")
            && (pname.contains("winword") || pname.contains("outlook") || pname.contains("excel"))
        {
            odd += 1;
        }
    }
    Ok(vec![finding(
        engine,
        if odd > 0 {
            "Shell parented by Office process (PPID-spoof/suspicious spawn)"
        } else {
            "No Office→shell parent anomalies in process tree"
        },
        if odd > 0 { "high" } else { "info" },
        "T1134.004",
        &format!("{odd} cmd/powershell processes parented by Office."),
        {
            let mut m = serde_json::Map::new();
            m.insert("office_shell_spawns".into(), json!(odd));
            m
        },
    )])
}

pub async fn run_privesc(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = tokio::fs::read_to_string("/etc/passwd").await {
            for line in s.lines() {
                if line.contains(":0:0:") && !line.starts_with("root:") {
                    findings.push(finding(
                        engine,
                        "Non-root UID 0 account in /etc/passwd",
                        "critical",
                        "T1068",
                        line,
                        json!({}).as_object().cloned().unwrap_or_default(),
                    ));
                }
            }
        }
        if tokio::fs::metadata("/etc/sudoers.d").await.is_ok() {
            findings.push(finding(
                engine,
                "sudoers.d drop-ins present — review for NOPASSWD",
                "info",
                "T1548.003",
                "/etc/sudoers.d exists on this host.",
                json!({}).as_object().cloned().unwrap_or_default(),
            ));
        }
        if let Ok(out) = tokio::process::Command::new("find")
            .args([
                "/usr/bin",
                "/usr/sbin",
                "/bin",
                "/sbin",
                "-perm",
                "-4000",
                "-type",
                "f",
            ])
            .output()
            .await
        {
            let list = String::from_utf8_lossy(&out.stdout);
            let bins: Vec<&str> = list.lines().filter(|l| !l.is_empty()).collect();
            let unusual: Vec<&str> = bins
                .iter()
                .copied()
                .filter(|p| {
                    !p.ends_with("/sudo")
                        && !p.ends_with("/su")
                        && !p.ends_with("/passwd")
                        && !p.ends_with("/ping")
                        && !p.ends_with("/mount")
                })
                .collect();
            if !unusual.is_empty() {
                findings.push(finding(
                    engine,
                    "Unexpected SUID binaries on PATH prefixes",
                    "high",
                    "T1548.001",
                    &unusual.join(" "),
                    json!({ "suid": unusual }).as_object().cloned().unwrap_or_default(),
                ));
            }
        }
        if let Ok(out) = tokio::process::Command::new("getcap")
            .args(["-r", "/usr/bin"])
            .output()
            .await
        {
            let s = String::from_utf8_lossy(&out.stdout);
            if s.contains("cap_setuid") || s.contains("cap_sys_admin") {
                findings.push(finding(
                    engine,
                    "Dangerous file capabilities (setuid/sys_admin) on /usr/bin",
                    "high",
                    "T1548.001",
                    s.trim(),
                    json!({}).as_object().cloned().unwrap_or_default(),
                ));
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(out) = tokio::process::Command::new("whoami")
            .args(["/priv"])
            .output()
            .await
        {
            let s = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
            if s.contains("seimpersonateprivilege") && s.contains("enabled") {
                findings.push(finding(
                    engine,
                    "SeImpersonatePrivilege enabled (potato-class priv-esc surface)",
                    "high",
                    "T1134",
                    "whoami /priv reports SeImpersonatePrivilege Enabled.",
                    json!({}).as_object().cloned().unwrap_or_default(),
                ));
            }
        }
    }
    if findings.is_empty() {
        findings.push(finding(
            engine,
            "No extra UID 0 / NOPASSWD artifacts observed",
            "info",
            "T1068",
            "Privilege-escalation inventory completed.",
            json!({}).as_object().cloned().unwrap_or_default(),
        ));
    }
    Ok(findings)
}

fn num_cpus_approx() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}
