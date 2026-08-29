//! TCP listen / accept tuning: Nagle off + keepalive so cockpit telemetry is not delayed.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

/// Idle time before the first keepalive probe (Linux `TCP_KEEPIDLE`).
const KEEPALIVE_IDLE: Duration = Duration::from_secs(45);
/// Interval between subsequent probes (`TCP_KEEPINTVL`).
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// Failed probes before the kernel drops the socket (`TCP_KEEPCNT`, Linux/macOS).
const KEEPALIVE_RETRIES: u32 = 5;
/// Accept backlog — large enough for bursty agent reconnects without SYN drops.
/// The kernel silently truncates `listen()` to `net.core.somaxconn` (often 128/4096
/// depending on distro). We read somaxconn and pass the effective value so we do
/// not pretend 4096 when the OS will only queue 128.
pub const LISTEN_BACKLOG: i32 = 4096;

#[must_use]
pub fn parse_somaxconn(text: &str) -> Option<i32> {
    text.trim().parse::<i32>().ok().filter(|&n| n > 0)
}

#[must_use]
pub fn effective_listen_backlog(requested: i32, somaxconn: Option<i32>) -> i32 {
    let requested = requested.max(1);
    match somaxconn {
        Some(max) if max < requested => max.max(1),
        _ => requested,
    }
}

fn os_somaxconn() -> Option<i32> {
    #[cfg(target_os = "linux")]
    {
        return std::fs::read_to_string("/proc/sys/net/core/somaxconn")
            .ok()
            .and_then(|s| parse_somaxconn(&s));
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn keepalive_spec() -> socket2::TcpKeepalive {
    let ka = socket2::TcpKeepalive::new()
        .with_time(KEEPALIVE_IDLE)
        .with_interval(KEEPALIVE_INTERVAL);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        return ka.with_retries(KEEPALIVE_RETRIES);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        ka
    }
}

/// Apply TCP_NODELAY + SO_KEEPALIVE on an accepted (or connected) stream.
pub fn tune_tcp_stream(stream: &TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(target: "http", error = %e, "tcp_nodelay failed");
    }
    let sock = socket2::SockRef::from(stream);
    if let Err(e) = sock.set_keepalive(true) {
        tracing::debug!(target: "http", error = %e, "so_keepalive failed");
    }
    if let Err(e) = sock.set_tcp_keepalive(&keepalive_spec()) {
        tracing::debug!(target: "http", error = %e, "tcp_keepalive failed");
    }
}

/// Bind `0.0.0.0:port` (or `[::]:port`) with reuse, nodelay, keepalive, and a large backlog.
pub fn bind_http_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    {
        let _ = socket.set_reuse_port(true);
    }
    socket.set_tcp_nodelay(true)?;
    socket.set_keepalive(true)?;
    let _ = socket.set_tcp_keepalive(&keepalive_spec());
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    let somax = os_somaxconn();
    let backlog = effective_listen_backlog(LISTEN_BACKLOG, somax);
    if somax.is_some_and(|m| m < LISTEN_BACKLOG) {
        tracing::error!(
            target: "http",
            requested = LISTEN_BACKLOG,
            somaxconn = ?somax,
            effective = backlog,
            "listen backlog truncated by net.core.somaxconn — SYN/WSS drops under agent reconnect bursts. Host: sysctl -w net.core.somaxconn=4096 net.ipv4.tcp_max_syn_backlog=4096 (see deploy/sysctl.d/99-weissman-listen.conf)"
        );
    } else {
        tracing::info!(
            target: "http",
            backlog,
            somaxconn = ?somax,
            "TCP listen backlog"
        );
    }
    socket.listen(backlog)?;
    TcpListener::from_std(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_sets_nodelay_on_accepted_socket() {
        let listener = bind_http_listener(SocketAddr::from(([127, 0, 0, 1], 0))).expect("bind");
        let addr = listener.local_addr().expect("local");
        let client = TcpStream::connect(addr).await.expect("connect");
        let (server, _) = listener.accept().await.expect("accept");
        tune_tcp_stream(&server);
        tune_tcp_stream(&client);
        assert!(server.nodelay().expect("server nodelay"));
        assert!(client.nodelay().expect("client nodelay"));
    }

    #[test]
    fn somaxconn_truncates_requested_backlog() {
        assert_eq!(effective_listen_backlog(4096, Some(128)), 128);
        assert_eq!(effective_listen_backlog(4096, Some(4096)), 4096);
        assert_eq!(effective_listen_backlog(4096, Some(8192)), 4096);
        assert_eq!(effective_listen_backlog(4096, None), 4096);
        assert_eq!(parse_somaxconn("128\n"), Some(128));
        assert_eq!(parse_somaxconn("0"), None);
    }
}
