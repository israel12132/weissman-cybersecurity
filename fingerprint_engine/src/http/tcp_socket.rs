//! TCP listen / accept tuning: Nagle off + keepalive so cockpit telemetry is not delayed.
//! Payload-too-large paths arm an abrupt RST (`SO_LINGER 0` + `shutdown(Both)`) so an
//! ALB/proxy cannot keep filling VPC buffers after a graceful `Connection: close`.

use axum::http::Request;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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

/// Apply `SO_LINGER { linger: 0 }` then `shutdown(Both)` — kernel sends RST, not FIN.
pub fn apply_tcp_rst(sock: &socket2::SockRef<'_>) {
    let _ = sock.set_linger(Some(Duration::ZERO));
    let _ = sock.shutdown(std::net::Shutdown::Both);
}

/// Dup-handle for tests and optional request extensions. `abort()` is the same RST
/// sequence as [`abort_tcp_peer`].
#[derive(Clone)]
pub struct TcpRstHandle {
    inner: Arc<RstInner>,
}

struct RstInner {
    socket: Option<socket2::Socket>,
    armed: AtomicBool,
}

impl TcpRstHandle {
    /// Handle with no kernel socket (oneshot tests). `abort()` still flips [`Self::is_armed`].
    #[must_use]
    pub fn noop() -> Self {
        Self {
            inner: Arc::new(RstInner {
                socket: None,
                armed: AtomicBool::new(false),
            }),
        }
    }

    /// Duplicate the kernel socket so linger/shutdown apply to the shared TCP PCB.
    pub fn from_tcp_stream(stream: &TcpStream) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::fd::AsFd;
            let owned = stream.as_fd().try_clone_to_owned()?;
            let socket = socket2::Socket::from(owned);
            return Ok(Self {
                inner: Arc::new(RstInner {
                    socket: Some(socket),
                    armed: AtomicBool::new(false),
                }),
            });
        }
        #[cfg(not(unix))]
        {
            let _ = stream;
            Ok(Self::noop())
        }
    }

    pub fn abort(&self) {
        self.inner.armed.store(true, Ordering::SeqCst);
        if let Some(ref socket) = self.inner.socket {
            apply_tcp_rst(&socket2::SockRef::from(socket));
        }
    }

    #[must_use]
    pub fn is_armed(&self) -> bool {
        self.inner.armed.load(Ordering::SeqCst)
    }
}

/// RST the request's TCP peer via the handle injected at accept
/// ([`crate::http::http_serve_loop`]). No-ops on oneshot tests without a handle.
pub fn abrupt_close_http_peer<B>(req: &Request<B>) {
    if let Some(h) = req.extensions().get::<TcpRstHandle>() {
        h.abort();
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

    #[test]
    fn rst_handle_noop_arms_without_socket() {
        let h = TcpRstHandle::noop();
        assert!(!h.is_armed());
        h.abort();
        assert!(h.is_armed());
    }

    #[tokio::test]
    async fn abort_handle_resets_accepted_peer() {
        use tokio::io::AsyncReadExt;
        let listener = bind_http_listener(SocketAddr::from(([127, 0, 0, 1], 0))).expect("bind");
        let addr = listener.local_addr().expect("local");
        let mut client = TcpStream::connect(addr).await.expect("connect");
        let (server, _) = listener.accept().await.expect("accept");
        let handle = TcpRstHandle::from_tcp_stream(&server).expect("dup");
        handle.abort();
        drop(server);
        let mut buf = [0u8; 16];
        let result = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await;
        match result {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("peer sent {n} bytes after RST"),
            Err(_) => panic!("timed out waiting for TCP reset"),
        }
    }

    #[tokio::test]
    async fn abrupt_close_http_peer_prefers_request_handle() {
        let h = TcpRstHandle::noop();
        let mut req = Request::new(());
        req.extensions_mut().insert(h.clone());
        abrupt_close_http_peer(&req);
        assert!(h.is_armed());
    }
}
