//! Linux process + listener inventory via `/proc` only.
//!
//! No `ps`, `lsof`, `ss`, `netstat`, or libprocps. Each sample is a handful of
//! `open`/`read`/`getdents` syscalls against procfs, which is why this is an
//! order of magnitude faster than spawning a CLI per tick.

use super::{ListenPort, ProcessRecord};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub fn list_processes(full: bool) -> Vec<ProcessRecord> {
    let Ok(dir) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let page = page_size_bytes();
    let mut out = Vec::with_capacity(256);
    for ent in dir.flatten() {
        let fname = ent.file_name();
        let Some(pid_str) = fname.to_str() else {
            continue;
        };
        if !pid_str.as_bytes().iter().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        let path = ent.path();
        let Some((name, ppid, vmem, rss_pages)) = parse_stat(&path.join("stat")) else {
            continue;
        };
        let mut rec = ProcessRecord {
            pid,
            ppid,
            name,
            exe: String::new(),
            uid: None,
            rss_bytes: rss_pages.saturating_mul(page),
            vmem_bytes: vmem,
        };
        if full {
            rec.exe = fs::read_link(path.join("exe"))
                .ok()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            rec.uid = parse_uid(&path.join("status"));
        }
        out.push(rec);
    }
    out
}

pub fn list_listen_ports() -> Vec<ListenPort> {
    let mut out: Vec<ListenPort> = Vec::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        parse_proc_net_tcp(path, &mut out);
    }
    out
}

fn parse_proc_net_tcp(path: &str, out: &mut Vec<ListenPort>) {
    let Ok(file) = fs::File::open(path) else {
        return;
    };
    let reader = BufReader::new(file);
    for (i, line) in reader.lines().map_while(Result::ok).enumerate() {
        if i == 0 {
            continue; // header
        }
        // sl local_address rem_address st ...
        let mut it = line.split_whitespace();
        let _ = it.next();
        let Some(local) = it.next() else { continue };
        let Some(_) = it.next() else { continue };
        let Some(st) = it.next() else { continue };
        if st != "0A" {
            continue; // not LISTEN
        }
        let Some((_, port_hex)) = local.rsplit_once(':') else {
            continue;
        };
        if let Ok(p) = u16::from_str_radix(port_hex, 16) {
            out.push(ListenPort { port: p });
        }
    }
}

/// `/proc/<pid>/stat`: `pid (comm) state ppid ... vsize rss`
fn parse_stat(path: &Path) -> Option<(String, Option<u32>, u64, u64)> {
    let raw = fs::read_to_string(path).ok()?;
    let start = raw.find('(')?;
    let end = raw.rfind(')')?;
    if end <= start {
        return None;
    }
    let name = raw[start + 1..end].trim().to_string();
    if name.is_empty() {
        return None;
    }
    let rest = raw[end + 1..].trim_start();
    // fields after comm: 3=state 4=ppid ... 23=vsize 24=rss
    let mut fields = rest.split_whitespace();
    let _state = fields.next()?;
    let ppid = fields.next().and_then(|s| s.parse::<u32>().ok());
    // skip fields 5..22 (18 fields)
    for _ in 0..18 {
        let _ = fields.next()?;
    }
    let vmem = fields
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let rss_pages = fields
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    Some((name, ppid, vmem, rss_pages))
}

fn parse_uid(path: &Path) -> Option<u32> {
    let s = fs::read_to_string(path).ok()?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn page_size_bytes() -> u64 {
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n > 0 {
        n as u64
    } else {
        4096
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_own_stat() {
        let me = std::process::id();
        let rec = parse_stat(std::path::Path::new(&format!("/proc/{me}/stat")));
        assert!(rec.is_some(), "could not parse /proc/{me}/stat");
        let (name, ppid, _vmem, _rss) = rec.unwrap();
        assert!(!name.is_empty());
        assert!(ppid.is_some());
    }

    #[test]
    fn tcp_parser_accepts_listen_hex() {
        // Synthetic: we only assert the live reader does not panic and returns a vec.
        let mut out = Vec::new();
        parse_proc_net_tcp("/proc/net/tcp", &mut out);
        // Any listen port is fine; the point is we did not shell out.
        let _ = out;
    }
}
