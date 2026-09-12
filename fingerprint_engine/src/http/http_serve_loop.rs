//! HTTP accept loop that injects [`TcpRstHandle`] + `ConnectInfo<SocketAddr>`.
//!
//! Axum 0.7's `IncomingStream` does not expose the `TcpStream`, so `axum::serve`
//! cannot arm `SO_LINGER 0`. We accept ourselves, dup the fd (safe `AsFd`), and
//! serve with hyper-util — same upgrades + graceful shutdown as Axum.

use crate::http::tcp_socket::{tune_tcp_stream, TcpRstHandle};
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::Request;
use axum::Extension;
use axum::Router;
use futures::FutureExt;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use std::future::{poll_fn, Future};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tower::{Service, ServiceBuilder, ServiceExt};

fn is_connection_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}

async fn tcp_accept(listener: &TcpListener) -> Option<(TcpStream, SocketAddr)> {
    match listener.accept().await {
        Ok(conn) => Some(conn),
        Err(e) => {
            if is_connection_error(&e) {
                return None;
            }
            tracing::error!(target: "http", error = %e, "accept error");
            tokio::time::sleep(Duration::from_secs(1)).await;
            None
        }
    }
}

/// Serve `app` until `shutdown` resolves. Each accepted socket gets a [`TcpRstHandle`]
/// so payload-too-large middleware can RST instead of a graceful FIN.
pub async fn serve_with_peer_rst(
    listener: TcpListener,
    app: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    let mut make_service = app.into_make_service();

    let (signal_tx, signal_rx) = watch::channel(());
    let signal_tx = Arc::new(signal_tx);
    tokio::spawn(async move {
        shutdown.await;
        drop(signal_rx);
    });

    let (close_tx, close_rx) = watch::channel(());

    loop {
        let (tcp_stream, remote_addr) = tokio::select! {
            conn = tcp_accept(&listener) => {
                match conn {
                    Some(conn) => conn,
                    None => continue,
                }
            }
            _ = signal_tx.closed() => {
                tracing::info!(target: "http", "shutdown signal — stop accepting");
                break;
            }
        };

        tune_tcp_stream(&tcp_stream);
        let rst = TcpRstHandle::from_tcp_stream(&tcp_stream).unwrap_or_else(|e| {
            tracing::error!(target: "http", error = %e, "TCP RST handle dup failed");
            TcpRstHandle::noop()
        });

        poll_fn(|cx| Service::<()>::poll_ready(&mut make_service, cx))
            .await
            .unwrap_or_else(|err| match err {});

        let router_svc = match make_service.call(()).await {
            Ok(s) => s,
            Err(err) => match err {},
        };

        let tower_service = ServiceBuilder::new()
            .layer(Extension(ConnectInfo(remote_addr)))
            .layer(Extension(rst))
            .service(router_svc)
            .map_request(|req: Request<Incoming>| req.map(Body::new));

        let hyper_service = TowerToHyperService::new(tower_service);
        let io = TokioIo::new(tcp_stream);
        let signal_tx = Arc::clone(&signal_tx);
        let close_rx = close_rx.clone();

        tokio::spawn(async move {
            let builder = Builder::new(TokioExecutor::new());
            let conn = builder.serve_connection_with_upgrades(io, hyper_service);
            futures::pin_mut!(conn);
            let signal_closed = signal_tx.closed().fuse();
            futures::pin_mut!(signal_closed);
            loop {
                tokio::select! {
                    result = conn.as_mut() => {
                        if let Err(err) = result {
                            tracing::debug!(target: "http", error = %err, peer = %remote_addr, "connection closed");
                        }
                        break;
                    }
                    _ = &mut signal_closed => {
                        conn.as_mut().graceful_shutdown();
                    }
                }
            }
            drop(close_rx);
        });
    }

    drop(close_rx);
    drop(listener);
    close_tx.closed().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::tcp_socket::bind_http_listener;
    use axum::routing::{get, post};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn serve_injects_rst_handle_and_connect_info() {
        let listener = bind_http_listener(SocketAddr::from(([127, 0, 0, 1], 0))).expect("bind");
        let addr = listener.local_addr().expect("local");
        let app = Router::new().route(
            "/",
            get(
                |ConnectInfo(peer): ConnectInfo<SocketAddr>,
                 Extension(rst): Extension<TcpRstHandle>| async move {
                    format!("{peer}|armed={}", rst.is_armed())
                },
            ),
        );
        tokio::spawn(async move {
            let _ = serve_with_peer_rst(listener, app, std::future::pending()).await;
        });
        let url = format!("http://{addr}/");
        let body = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(resp) = reqwest::get(&url).await {
                    return resp.text().await.unwrap();
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("server up");
        assert!(body.contains("|armed=false"), "got {body}");
        assert!(body.contains("127.0.0.1:"), "got {body}");
    }

    #[tokio::test]
    async fn payload_too_large_resets_tcp() {
        let listener = bind_http_listener(SocketAddr::from(([127, 0, 0, 1], 0))).expect("bind");
        let addr = listener.local_addr().expect("local");
        let app = Router::new().route(
            "/",
            post(|Extension(rst): Extension<TcpRstHandle>| async move {
                rst.abort();
                (
                    axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                    [(axum::http::header::CONNECTION, "close")],
                    "too large",
                )
            }),
        );
        tokio::spawn(async move {
            let _ = serve_with_peer_rst(listener, app, std::future::pending()).await;
        });

        let mut client = TcpStream::connect(addr).await.expect("connect");
        client
            .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}")
            .await
            .expect("write");
        let mut buf = [0u8; 64];
        let result = tokio::time::timeout(Duration::from_secs(3), client.read(&mut buf)).await;
        match result {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(_)) => {
                // 413 may race the RST; a second read must fail or EOF.
                let r2 = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await;
                match r2 {
                    Ok(Ok(0)) | Ok(Err(_)) => {}
                    other => panic!("connection still open after RST: {other:?}"),
                }
            }
            Err(_) => panic!("timed out waiting for RST"),
        }
    }
}
