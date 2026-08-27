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
const LISTEN_BACKLOG: i32 = 4096;

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
    socket.listen(LISTEN_BACKLOG)?;
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
}
