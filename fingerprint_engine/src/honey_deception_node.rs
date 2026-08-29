//! High-fidelity honeynet decoys — simulated admin portal + debug-shell FSM.
//!
//! Nothing here executes attacker input. The filesystem, users, and credentials
//! are fictional VIP-looking bait. Every command is recorded by the caller.

use serde_json::{json, Value};
use std::collections::HashMap;

use crate::honey_routing::{DECOY_ADMIN, DECOY_FINGERPRINT};

const HOSTNAME: &str = "gw-core-01.internal.weissman-vip";
const USER: &str = "ops-admin";
const HOME: &str = "/home/ops-admin";

#[derive(Debug, Clone)]
pub struct ShellState {
    pub cwd: String,
}

impl Default for ShellState {
    fn default() -> Self {
        Self {
            cwd: HOME.to_string(),
        }
    }
}

fn vfs() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::new();
    m.insert(
        "/etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\n\
ops-admin:x:1001:1001:VIP Operations:/home/ops-admin:/bin/bash\n\
backup-svc:x:1002:1002:Backup Service:/opt/backup:/usr/sbin/nologin\n\
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
    );
    m.insert("/etc/hostname", HOSTNAME);
    m.insert(
        "/home/ops-admin/.ssh/id_rsa",
        "-----BEGIN OPENSSH PRIVATE KEY-----\n\
HONEYTOKEN-DO-NOT-USE-b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n\
AAABlwAAAAdzc2gtcnNhAAAAAwEAAQAAAYEAsimulatedkeynotrealweissmanhoneynet\n\
-----END OPENSSH PRIVATE KEY-----\n",
    );
    m.insert(
        "/home/ops-admin/.ssh/authorized_keys",
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC-honeytoken-not-a-real-key ops-admin@gw-core-01\n",
    );
    m.insert(
        "/opt/weissman/config.yaml",
        "# INTERNAL — VIP network only\napi_listen: 10.8.0.14:8443\nadmin_token: wmn-ht-AKIAHONEYTOKENADMIN\ndb: postgres://honey:not-real@10.8.0.22/core\n",
    );
    m.insert(
        "/var/log/auth.log",
        "Aug 27 04:11:02 gw-core-01 sshd[4412]: Accepted publickey for ops-admin from 10.8.0.4 port 51222\n\
Aug 27 04:12:18 gw-core-01 sudo: ops-admin : TTY=pts/0 ; PWD=/home/ops-admin ; USER=root ; COMMAND=/usr/bin/systemctl status weissman-gateway\n",
    );
    m.insert(
        "/home/ops-admin/.bash_history",
        "systemctl status weissman-gateway\njournalctl -u weissman-gateway -n 50\ncat /opt/weissman/config.yaml\n",
    );
    m.insert(
        "/home/ops-admin/notes.txt",
        "jump host 10.8.0.4 — do not expose VIP ACL\n",
    );
    m
}

fn dir_listing(path: &str) -> &'static str {
    match path {
        "/" => "bin  boot  dev  etc  home  opt  proc  root  tmp  usr  var\n",
        "/home" => "ops-admin\n",
        "/home/ops-admin" => ".bash_history  .ssh  notes.txt\n",
        "/home/ops-admin/.ssh" => "authorized_keys  id_rsa  id_rsa.pub\n",
        "/etc" => "hostname  passwd  shadow  ssh\n",
        "/opt" => "weissman\n",
        "/opt/weissman" => "config.yaml  bin  logs\n",
        "/var" => "log  tmp\n",
        "/var/log" => "auth.log  syslog  weissman\n",
        _ => "",
    }
}

fn resolve(cwd: &str, arg: &str) -> String {
    if arg.starts_with('/') {
        normalize_fs(arg)
    } else if arg == "." {
        cwd.to_string()
    } else if arg == ".." {
        parent(cwd)
    } else {
        normalize_fs(&format!("{cwd}/{arg}"))
    }
}

fn parent(path: &str) -> String {
    if path == "/" {
        return "/".into();
    }
    let trimmed = path.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some(("", _)) => "/".into(),
        Some((p, _)) => {
            if p.is_empty() {
                "/".into()
            } else {
                p.to_string()
            }
        }
        None => "/".into(),
    }
}

fn normalize_fs(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            out.pop();
        } else {
            out.push(part);
        }
    }
    if out.is_empty() {
        "/".into()
    } else {
        format!("/{}", out.join("/"))
    }
}

/// Execute simulated shell input (AST via `nom`). Never runs a real process.
pub fn run_shell(state: &ShellState, raw: &str) -> (String, ShellState) {
    let (out, err, _, st) = run_shell_detailed(state, raw);
    (format!("{err}{out}"), st)
}

pub fn run_shell_detailed(state: &ShellState, raw: &str) -> (String, String, i32, ShellState) {
    let line = raw.trim();
    if line.is_empty() {
        return (String::new(), String::new(), 0, state.clone());
    }
    match crate::honey_shell_ast::parse_script(line) {
        Err(e) => (
            String::new(),
            crate::honey_shell_ast::parse_error_text(&e),
            2,
            state.clone(),
        ),
        Ok(script) => {
            let mut st = state.clone();
            let (out, err, code) = crate::honey_shell_ast::eval_script(&script, |cmd, stdin| {
                exec_simple(&mut st, cmd.argv.as_slice(), stdin)
            });
            (out, err, code, st)
        }
    }
}

fn exec_simple(st: &mut ShellState, argv: &[String], stdin: Option<&str>) -> (String, String, i32) {
    if argv.is_empty() {
        return (String::new(), String::new(), 0);
    }
    let cmd = argv[0].as_str();
    let args: Vec<&str> = argv.iter().skip(1).map(String::as_str).collect();
    let files = vfs();
    let out = match cmd {
        "help" | "?" => {
            "Builtins: ls cd pwd cat whoami id uname ps env netstat ifconfig history sudo help exit\n".into()
        }
        "echo" => {
            let mut s = args.join(" ");
            s.push('\n');
            s
        }
        "true" => String::new(),
        "false" => {
            return (String::new(), String::new(), 1);
        }
        "grep" => {
            let pat = args.iter().copied().find(|a| !a.starts_with('-')).unwrap_or("");
            let hay = stdin.unwrap_or("");
            let matched: String = hay.lines().filter(|l| l.contains(pat)).map(|l| format!("{l}\n")).collect();
            let code = if matched.is_empty() { 1 } else { 0 };
            return (matched, String::new(), code);
        }
        "head" => {
            let n = args
                .iter()
                .find_map(|a| a.strip_prefix("-n").and_then(|s| s.parse().ok()))
                .or_else(|| {
                    args.windows(2)
                        .find(|w| w[0] == "-n")
                        .and_then(|w| w[1].parse().ok())
                })
                .unwrap_or(10usize);
            let hay = stdin.unwrap_or("");
            let out: String = hay.lines().take(n).map(|l| format!("{l}\n")).collect();
            return (out, String::new(), 0);
        }
        "wc" => {
            let hay = stdin.unwrap_or("");
            let lines = hay.lines().count();
            return (format!("{lines}\n"), String::new(), 0);
        }
        "whoami" => format!("{USER}\n"),
        "id" => format!("uid=1001({USER}) gid=1001({USER}) groups=1001({USER}),27(sudo)\n"),
        "hostname" | "uname" => {
            if cmd == "uname" && args.first().copied() == Some("-a") {
                format!("Linux {HOSTNAME} 6.8.0-51-generic #51-Ubuntu SMP x86_64 GNU/Linux\n")
            } else if cmd == "uname" {
                "Linux\n".into()
            } else {
                format!("{HOSTNAME}\n")
            }
        }
        "pwd" => format!("{}\n", st.cwd),
        "cd" => {
            let target = resolve(&st.cwd, args.first().copied().unwrap_or(HOME));
            if dir_listing(&target).is_empty() && !files.contains_key(target.as_str()) && target != HOME {
                format!("bash: cd: {target}: No such file or directory\n")
            } else {
                st.cwd = if files.contains_key(target.as_str()) {
                    parent(&target)
                } else {
                    target
                };
                String::new()
            }
        }
        "ls" => {
            let target = resolve(&st.cwd, args.iter().copied().find(|a| !a.starts_with('-')).unwrap_or("."));
            let listing = dir_listing(&target);
            if listing.is_empty() {
                if files.contains_key(target.as_str()) {
                    format!("{}\n", target.rsplit('/').next().unwrap_or(&target))
                } else {
                    format!("ls: cannot access '{target}': No such file or directory\n")
                }
            } else {
                listing.to_string()
            }
        }
        "cat" => {
            let Some(arg) = args.first() else {
                return ("cat: missing operand\n".into(), String::new(), 1);
            };
            let target = resolve(&st.cwd, arg);
            match files.get(target.as_str()) {
                Some(content) => (*content).to_string(),
                None => format!("cat: {target}: No such file or directory\n"),
            }
        }
        "ps" => {
            "  PID TTY          TIME CMD\n    1 ?        00:00:02 systemd\n  882 ?        00:00:11 weissman-gateway\n 4412 pts/0    00:00:00 bash\n".into()
        }
        "env" | "printenv" => {
            format!(
                "USER={USER}\nHOME={HOME}\nHOSTNAME={HOSTNAME}\nSHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\n"
            )
        }
        "netstat" | "ss" => {
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 10.8.0.14:8443          0.0.0.0:*               LISTEN\ntcp        0      0 10.8.0.14:22            0.0.0.0:*               LISTEN\n".into()
        }
        "ifconfig" | "ip" => {
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.8.0.14  netmask 255.255.255.0  broadcast 10.8.0.255\n".into()
        }
        "history" => files.get("/home/ops-admin/.bash_history").unwrap_or(&"").to_string(),
        "sudo" => "sudo: a password is required\n".into(),
        "exit" | "logout" => "logout\n".into(),
        "wget" | "curl" | "nc" | "ncat" | "nmap" | "ssh" | "scp" | "python" | "python3" | "bash" | "sh" => {
            format!("{cmd}: connection timed out — VIP ACL denied outbound (ticket NSG-4412)\n")
        }
        other => {
            return (
                String::new(),
                format!("bash: {other}: command not found\n"),
                127,
            );
        }
    };
    let code = if out.contains("No such file")
        || out.contains("missing operand")
        || out.contains("timed out")
        || out.contains("password is required")
    {
        1
    } else {
        0
    };
    (out, String::new(), code)
}

pub fn shell_banner() -> Value {
    json!({
        "ok": true,
        "service": "weissman-internal-debug",
        "hint": "POST JSON {\"cmd\":\"whoami\"} — restricted to Internal VIP network",
        "host": HOSTNAME,
        "user": USER,
        "cwd": HOME,
        "notice": "Session recorded for change-control (SOX).",
    })
}

pub fn shell_exec_json(cmd: &str, cwd: &str) -> Value {
    let state = ShellState {
        cwd: cwd.to_string(),
    };
    let (stdout, stderr, exit_code, next) = run_shell_detailed(&state, cmd);
    json!({
        "ok": true,
        "host": HOSTNAME,
        "user": USER,
        "cwd": next.cwd,
        "cmd": cmd,
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
    })
}

pub fn admin_login_error() -> Value {
    json!({
        "ok": false,
        "error": "Access restricted to Internal VIP network",
        "code": "VIP_ACL",
        "hint": "Database Handshake Timed Out — retry from jump-host 10.8.0.4",
        "ticket": "NSG-4412",
        "mfa": "required",
    })
}

/// Luxury-looking admin portal. Passive JS profiles the attacking browser only
/// (this page is served *to* the attacker on our decoy URL).
pub fn admin_portal_html() -> String {
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Weissman · Internal VIP Console</title>
<style>
  :root {{ --bg:#070b12; --card:#101826; --line:rgba(56,189,248,.28); --text:#e2e8f0; --muted:#64748b; --accent:#38bdf8; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; min-height:100vh; background:radial-gradient(1200px 600px at 10% -10%, #0e3a4a 0%, var(--bg) 45%);
         color:var(--text); font-family:ui-sans-serif,system-ui,sans-serif; }}
  .wrap {{ max-width:420px; margin:12vh auto; padding:28px 28px 22px; background:linear-gradient(180deg, rgba(16,24,38,.95), rgba(8,12,20,.92));
           border:1px solid var(--line); border-radius:18px; box-shadow:0 0 80px rgba(56,189,248,.12); }}
  h1 {{ font-size:15px; letter-spacing:.22em; text-transform:uppercase; color:var(--accent); margin:0 0 6px; }}
  p.sub {{ color:var(--muted); font-size:12px; margin:0 0 22px; }}
  label {{ display:block; font-size:11px; color:var(--muted); letter-spacing:.08em; text-transform:uppercase; margin:12px 0 6px; }}
  input {{ width:100%; padding:11px 12px; border-radius:10px; border:1px solid #1e293b; background:#0b1220; color:var(--text); }}
  button {{ width:100%; margin-top:18px; padding:12px; border:0; border-radius:10px; font-weight:600; letter-spacing:.08em;
            text-transform:uppercase; background:linear-gradient(90deg,#0891b2,#38bdf8); color:#041016; cursor:pointer; }}
  .err {{ display:none; margin-top:14px; font-size:12px; color:#fca5a5; background:rgba(239,68,68,.12); border:1px solid rgba(239,68,68,.35);
          padding:10px 12px; border-radius:10px; }}
  footer {{ margin-top:18px; font-size:10px; color:#334155; text-align:center; }}
</style>
</head>
<body>
  <div class="wrap">
    <h1>Internal VIP Console</h1>
    <p class="sub">Restricted operations plane · jump-host required</p>
    <form id="f" autocomplete="off">
      <label>Operator identity</label>
      <input name="email" type="email" placeholder="ops-admin@internal.weissman-vip" required/>
      <label>Passphrase</label>
      <input name="password" type="password" placeholder="••••••••" required/>
      <button type="submit">Authenticate</button>
      <div class="err" id="e">Access restricted to Internal VIP network. Database Handshake Timed Out.</div>
    </form>
    <footer>Change-control session · SOX / Directive 361</footer>
  </div>
  <script>
  (function() {{
    function collect() {{
      var p = {{
        ua: navigator.userAgent,
        lang: navigator.language,
        langs: navigator.languages,
        platform: navigator.platform,
        hw: navigator.hardwareConcurrency || null,
        mem: navigator.deviceMemory || null,
        tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
        screen: {{ w: screen.width, h: screen.height, dpr: window.devicePixelRatio, color: screen.colorDepth }},
        touch: navigator.maxTouchPoints || 0,
        webgl: null,
        canvas: null,
        audio: null
      }};
      try {{
        var c = document.createElement('canvas');
        var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
        if (gl) {{
          var ext = gl.getExtension('WEBGL_debug_renderer_info');
          p.webgl = {{
            vendor: ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
            renderer: ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER)
          }};
        }}
        var ctx = c.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillText('wmn-vip', 2, 2);
        p.canvas = c.toDataURL().slice(-48);
      }} catch (e) {{}}
      try {{
        var ac = new (window.AudioContext || window.webkitAudioContext)();
        p.audio = {{ sr: ac.sampleRate, ch: ac.destination.maxChannelCount }};
        ac.close && ac.close();
      }} catch (e) {{}}
      return p;
    }}
    try {{
      fetch('{fp}', {{ method:'POST', headers:{{'content-type':'application/json'}}, body: JSON.stringify(collect()), credentials:'omit' }});
    }} catch (e) {{}}
    document.getElementById('f').addEventListener('submit', function(ev) {{
      ev.preventDefault();
      var fd = new FormData(ev.target);
      fetch('{admin}', {{
        method:'POST',
        headers:{{'content-type':'application/json'}},
        body: JSON.stringify({{ email: fd.get('email'), password: fd.get('password') }}),
        credentials:'omit'
      }}).then(function() {{
        document.getElementById('e').style.display = 'block';
      }}).catch(function() {{
        document.getElementById('e').style.display = 'block';
      }});
    }});
  }})();
  </script>
</body>
</html>
"##,
        fp = DECOY_FINGERPRINT,
        admin = DECOY_ADMIN
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whoami_is_fictional() {
        let (out, _) = run_shell(&ShellState::default(), "whoami");
        assert_eq!(out.trim(), USER);
        assert!(!out.contains("root"));
    }

    #[test]
    fn cat_passwd_is_bait_not_host() {
        let (out, _) = run_shell(&ShellState::default(), "cat /etc/passwd");
        assert!(out.contains("ops-admin"));
        assert!(!out.contains("ubuntu"));
    }

    #[test]
    fn cd_and_ls_work() {
        let (out, st) = run_shell(&ShellState::default(), "cd /opt/weissman");
        assert!(out.is_empty());
        let (ls, _) = run_shell(&st, "ls");
        assert!(ls.contains("config.yaml"));
    }

    #[test]
    fn unknown_binaries_do_not_execute() {
        let (out, _) = run_shell(&ShellState::default(), "rm -rf /");
        assert!(out.contains("command not found") || out.contains("timed out"));
    }

    #[test]
    fn ssh_is_acl_denied_not_executed() {
        let (out, _) = run_shell(&ShellState::default(), "ssh root@10.0.0.5");
        assert!(out.to_lowercase().contains("timed out") || out.to_lowercase().contains("denied"));
    }

    #[test]
    fn chained_semicolon_and_and_are_parsed() {
        let (out, _) = run_shell(&ShellState::default(), "whoami; id");
        assert!(out.contains(USER));
        assert!(out.contains("uid=1001"));
        let (out, _) = run_shell(&ShellState::default(), "echo 'test' && uname -a");
        assert!(out.contains("test"));
        assert!(out.contains("Linux"));
    }

    #[test]
    fn pipe_grep_is_simulated_not_host() {
        let (out, _) = run_shell(&ShellState::default(), "cat /etc/passwd | grep ops-admin");
        assert!(out.contains("ops-admin"));
        assert!(!out.contains("ubuntu"));
    }

    #[test]
    fn unmatched_quote_is_bash_error() {
        let (out, _) = run_shell(&ShellState::default(), "echo 'oops");
        assert!(out.contains("matching"));
        let (_, _, code, _) = run_shell_detailed(&ShellState::default(), "echo 'oops");
        assert_eq!(code, 2);
    }
}
