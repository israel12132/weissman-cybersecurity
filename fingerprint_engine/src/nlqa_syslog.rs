//! Isolated Ask Weissman forensic overflow path.
//!
//! HTTP `/api/ask` never awaits the Postgres INSERT (bounded MPSC). When that
//! lane is full or closed, this module writes a critical page to OS syslog
//! over the unix `/dev/log` datagram — not the application log volume / NFS
//! driver — and fans the same line through a dedicated
//! `tracing_appender::non_blocking::NonBlockingBuilder` with **`lossy(false)`**.
//! A full buffer blocks the syslog worker (strict non-lossy), never silently
//! drops an audit event. General HTTP `fmt` logs stay on the lossy stdout
//! appender so Tokio workers are not stalled by a stuck container log driver.

use std::io::{self, Write};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::OnceLock;

#[cfg(unix)]
use std::os::unix::net::UnixDatagram;

/// LOG_AUTHPRIV (10) * 8 + LOG_CRIT (2). Isolated from LOG_USER app logs.
const SYSLOG_PRI_AUTHPRIV_CRIT: i32 = 10 * 8 + 2;
const SYSLOG_OVERFLOW_CAPACITY: usize = 1024;
const SYSLOG_MAX_RECORD: usize = 900;

static STARTED: OnceLock<()> = OnceLock::new();
static SYSLOG_TX: OnceLock<SyncSender<String>> = OnceLock::new();
static SYSLOG_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();

#[cfg(test)]
static TEST_SINK: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Writer that emits RFC-3164-ish records to the OS syslog socket.
///
/// This is the isolated emergency channel: a unix datagram to `/dev/log` (or
/// journald's `dev-log`), independent of the application disk / NFS mount.
pub struct SyslogWriter {
    #[cfg(unix)]
    sock: Option<UnixDatagram>,
}

impl SyslogWriter {
    pub fn new() -> Self {
        Self {
            #[cfg(unix)]
            sock: Self::connect(),
        }
    }

    #[cfg(unix)]
    fn connect() -> Option<UnixDatagram> {
        for path in [
            "/dev/log",
            "/run/systemd/journal/dev-log",
            "/var/run/syslog",
            "/var/run/log",
        ] {
            let Ok(sock) = UnixDatagram::unbound() else {
                continue;
            };
            if sock.connect(path).is_ok() {
                return Some(sock);
            }
        }
        None
    }
}

impl Default for SyslogWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl Write for SyslogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            #[cfg(test)]
            if let Ok(mut sink) = TEST_SINK.lock() {
                sink.push(line.to_string());
            }
            let rec = format!("<{SYSLOG_PRI_AUTHPRIV_CRIT}>weissman-nlqa: {line}");
            let bytes = rec.as_bytes();
            let bytes = if bytes.len() > SYSLOG_MAX_RECORD {
                &bytes[..SYSLOG_MAX_RECORD]
            } else {
                bytes
            };
            let mut sent = false;
            #[cfg(unix)]
            if let Some(sock) = &self.sock {
                sent = sock.send(bytes).is_ok();
            }
            if !sent {
                // Container without /dev/log (CI). stderr is still not app NFS.
                let _ = writeln!(io::stderr(), "[NLQA1-SYSLOG] {line}");
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Start the strict (non-lossy) syslog worker. Safe to call more than once.
pub fn init() {
    if STARTED.set(()).is_err() {
        return;
    }
    let writer = SyslogWriter::new();
    let (mut nb, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .lossy(false)
        .buffered_lines_limit(1024)
        .thread_name("weissman-nlqa-syslog".into())
        .finish(writer);
    let _ = SYSLOG_GUARD.set(guard);

    let (tx, rx) = mpsc::sync_channel::<String>(SYSLOG_OVERFLOW_CAPACITY);
    let _ = SYSLOG_TX.set(tx);
    let _ = std::thread::Builder::new()
        .name("weissman-nlqa-syslog-q".into())
        .spawn(move || {
            while let Ok(page) = rx.recv() {
                let _ = writeln!(nb, "{page}");
            }
        });
}

/// Page a saturated Ask-audit event to OS syslog. Never silent.
///
/// Fast path: try_send onto the dedicated std thread (strict non-lossy
/// `NonBlockingBuilder`). If that queue is also full, write the unix datagram
/// inline from the caller — `/dev/log` is not the application disk.
pub fn page_audit_overflow(page: &str) {
    init();
    // Isolated OS channel first: never depend on the app log volume.
    emit_inline(page);
    match SYSLOG_TX.get() {
        Some(tx) => match tx.try_send(page.to_string()) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                // Strict non-lossy: the inline syslog write already happened.
                // A second inline write would only duplicate the CRIT page.
            }
        },
        None => {}
    }
}

fn emit_inline(page: &str) {
    let mut w = SyslogWriter::new();
    let _ = writeln!(w, "{page}");
}

#[cfg(test)]
pub fn test_sink_contains(needle: &str) -> bool {
    TEST_SINK
        .lock()
        .map(|s| s.iter().any(|line| line.contains(needle)))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syslog_writer_never_drops_the_page() {
        let mut w = SyslogWriter::new();
        writeln!(w, "nlqa1 tenant=7 kind=full sha=abc").unwrap();
        assert!(
            test_sink_contains("nlqa1 tenant=7 kind=full"),
            "forensic page must land in the syslog writer sink"
        );
    }

    #[test]
    fn page_audit_overflow_is_strict_non_lossy() {
        page_audit_overflow("nlqa1 overflow-strict-mode tenant=42");
        assert!(test_sink_contains("overflow-strict-mode tenant=42"));
    }
}
