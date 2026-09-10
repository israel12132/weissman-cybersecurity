//! PID-recycling TOCTOU guard for `/proc/<pid>/` reads.
//!
//! Linux reuses PIDs quickly. A comm/maps snapshot is only valid if the process
//! `starttime` (field 22 of `/proc/<pid>/stat`) is identical before and after the
//! read. `split_whitespace()` on the whole line is unsafe because `comm` may
//! contain spaces inside parentheses — parse after the last `)`.

use std::fs;
use std::io::{self, ErrorKind};

/// Clock ticks since boot when `pid` started (`/proc/<pid>/stat` field 22).
pub fn get_process_starttime(pid: u32) -> Result<u64, io::Error> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    parse_stat_starttime(&text).ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidData,
            "invalid /proc/<pid>/stat (no starttime)",
        )
    })
}

/// Parse field 22 (starttime) from a `/proc/<pid>/stat` line.
#[must_use]
pub fn parse_stat_starttime(stat: &str) -> Option<u64> {
    let rparen = stat.rfind(')')?;
    let rest = stat.get(rparen + 1..)?;
    // After comm: [0]=state (field 3) … starttime is field 22 → index 19.
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// Outcome of a starttime-bracketed `/proc/<pid>` read.
#[derive(Debug)]
pub enum PidRead<T> {
    /// starttime matched before and after.
    Ok(T),
    /// PID existed, then starttime changed or the task vanished — TOCTOU.
    Recycled,
    /// PID was never readable (gone, or EPERM before the first stat).
    Missing,
}

/// Run `f` only if `pid`'s starttime is stable across the call.
pub fn with_stable_pid<T>(pid: u32, f: impl FnOnce() -> T) -> PidRead<T> {
    let Ok(before) = get_process_starttime(pid) else {
        return PidRead::Missing;
    };
    if !starttime_plausible(before) {
        return PidRead::Missing;
    }
    let out = f();
    match get_process_starttime(pid) {
        Ok(after) if after == before => PidRead::Ok(out),
        _ => PidRead::Recycled,
    }
}

/// starttime is ticks since boot; it cannot exceed uptime·USER_HZ by a wide margin.
fn starttime_plausible(starttime: u64) -> bool {
    if starttime == 0 {
        return true; // PID 1 / kernel threads can be 0 on some kernels
    }
    let uptime = fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .unwrap_or(0.0);
    if uptime <= 0.0 {
        return true;
    }
    // USER_HZ is 100 on mainline x86_64; allow 10× slack for exotic HZ.
    let max_ticks = (uptime * 1000.0) as u64;
    starttime <= max_ticks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_field_22_even_when_comm_has_spaces() {
        // pid=42 comm="my proc name" then 20 fields, starttime is the 20th after comm = 99999
        let mut fields = vec![
            "S", "1", "1", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0",
        ];
        fields.push("99999"); // index 19 = starttime
        fields.push("0");
        let line = format!("42 (my proc name) {}", fields.join(" "));
        assert_eq!(parse_stat_starttime(&line), Some(99999));
    }

    #[test]
    fn split_whitespace_on_whole_line_would_be_wrong() {
        let line = "10 (a b c) S 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 4242 0";
        // Naive split would shift indexes because "a b c" is three tokens.
        assert_eq!(parse_stat_starttime(line), Some(4242));
    }

    #[test]
    fn self_pid_is_stable() {
        let pid = std::process::id();
        match with_stable_pid(pid, || {
            fs::read_to_string("/proc/self/comm").unwrap_or_default()
        }) {
            PidRead::Ok(comm) => assert!(!comm.trim().is_empty()),
            other => panic!("expected stable self pid, got {other:?}"),
        }
    }
}
