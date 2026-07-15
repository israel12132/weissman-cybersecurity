//! Shared WebSocket session primitives — RFC6455 + tokio-tungstenite (single `http` crate path).

use futures::{SinkExt, StreamExt};
use std::time::{Duration, Instant};
use tokio_tungstenite::{
    connect_async_tls_with_config,
    tungstenite::{
        client::IntoClientRequest,
        http::{header::HeaderName, HeaderValue},
        Message,
    },
    Connector,
};

#[derive(Clone, Debug, Default)]
pub struct WsConnectOpts {
    pub origin: Option<String>,
    pub auth: Vec<(String, String)>,
    pub subprotocol: Option<String>,
    pub read_ms: u64,
    pub max_messages: usize,
}

#[derive(Clone, Debug, Default)]
pub struct WsExchangeResult {
    pub connected: bool,
    pub sent: Vec<String>,
    pub received: Vec<String>,
    pub received_binary: Vec<Vec<u8>>,
    pub close_reason: Option<String>,
}

pub fn http_to_ws_url(http_url: &str) -> String {
    if let Some(rest) = http_url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = http_url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        format!("wss://{}", http_url.trim_start_matches('/'))
    }
}

pub fn build_ws_connector() -> Option<Connector> {
    let mut builder = native_tls::TlsConnector::builder();
    if weissman_core::tls_policy::danger_accept_invalid_certs() {
        builder.danger_accept_invalid_certs(true);
    }
    let tls = builder.build().ok()?;
    Some(Connector::NativeTls(tls))
}

fn preview(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

pub async fn connect_request(
    http_url: &str,
    opts: &WsConnectOpts,
) -> Option<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
> {
    let ws_url = http_to_ws_url(http_url);
    let mut request = ws_url.as_str().into_client_request().ok()?;
    if let Some(o) = opts.origin.clone() {
        request
            .headers_mut()
            .insert("Origin", HeaderValue::from_str(&o).ok()?);
    }
    if let Some(sp) = opts.subprotocol.clone() {
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", HeaderValue::from_str(&sp).ok()?);
    }
    for (k, v) in opts.auth.clone() {
        let name = HeaderName::from_bytes(k.as_bytes()).ok()?;
        let val = HeaderValue::from_str(&v).ok()?;
        request.headers_mut().insert(name, val);
    }
    let connector = build_ws_connector();
    let connect = connect_async_tls_with_config(request, None, false, connector);
    let timeout = Duration::from_millis(opts.read_ms.saturating_add(5000).clamp(2000, 20_000));
    tokio::time::timeout(timeout, connect)
        .await
        .ok()?
        .ok()
        .map(|(s, _)| s)
}

pub async fn exchange_frames(
    http_url: &str,
    opts: &WsConnectOpts,
    outbound_text: &[String],
    outbound_binary: &[Vec<u8>],
) -> Option<WsExchangeResult> {
    let mut ws = connect_request(http_url, opts).await?;
    let mut result = WsExchangeResult {
        connected: true,
        ..Default::default()
    };

    for msg in outbound_text {
        if ws.send(Message::text(msg.clone())).await.is_err() {
            break;
        }
        result.sent.push(preview(msg, 240));
    }
    for bin in outbound_binary {
        if ws.send(Message::binary(bin.clone())).await.is_err() {
            break;
        }
        result.sent.push(format!("[binary {}B]", bin.len()));
    }

    let deadline = Instant::now() + Duration::from_millis(opts.read_ms.clamp(500, 15_000));
    while result.received.len() + result.received_binary.len() < opts.max_messages
        && Instant::now() < deadline
    {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => result.received.push(preview(&t, 512)),
            Ok(Some(Ok(Message::Binary(b)))) if !b.is_empty() => {
                result.received_binary.push(b.to_vec());
            }
            Ok(Some(Ok(Message::Close(frame)))) => {
                result.close_reason = frame.map(|f| preview(&f.reason, 120));
                break;
            }
            Ok(Some(Ok(Message::Ping(_)))) | Ok(Some(Ok(Message::Pong(_)))) => {}
            Ok(Some(Ok(_))) => {}
            _ => break,
        }
    }
    let _ = ws.close(None).await;
    Some(result)
}

/// Single persistent WebSocket session — send/read multiple phases without reconnecting.
pub async fn exchange_phases(
    http_url: &str,
    opts: &WsConnectOpts,
    phases: &[Vec<String>],
) -> Option<WsExchangeResult> {
    let mut ws = connect_request(http_url, opts).await?;
    let mut result = WsExchangeResult {
        connected: true,
        ..Default::default()
    };
    let phase_budget = (opts.max_messages / phases.len().max(1)).max(1);
    for phase in phases {
        for msg in phase {
            if ws.send(Message::text(msg.clone())).await.is_err() {
                let _ = ws.close(None).await;
                return Some(result);
            }
            result.sent.push(preview(msg, 240));
        }
        let deadline = Instant::now()
            + Duration::from_millis((opts.read_ms / phases.len().max(1) as u64).clamp(300, 8000));
        while result.received.len() + result.received_binary.len() < opts.max_messages
            && Instant::now() < deadline
            && result.received.len() < phase_budget * (phases.len())
        {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, ws.next()).await {
                Ok(Some(Ok(Message::Text(t)))) => result.received.push(preview(&t, 512)),
                Ok(Some(Ok(Message::Binary(b)))) if !b.is_empty() => {
                    result.received_binary.push(b.to_vec());
                }
                Ok(Some(Ok(Message::Close(frame)))) => {
                    result.close_reason = frame.map(|f| preview(&f.reason, 120));
                    let _ = ws.close(None).await;
                    return Some(result);
                }
                Ok(Some(Ok(Message::Ping(_)))) | Ok(Some(Ok(Message::Pong(_)))) => {}
                Ok(Some(Ok(_))) => {}
                _ => break,
            }
        }
    }
    let _ = ws.close(None).await;
    Some(result)
}

/// RFC6455 client text frame encoding (masked, FIN=1, opcode=1).
pub fn encode_client_text_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(0x81);
    let mask_key = [0x37, 0xfa, 0x21, 0x3d];
    if payload.len() < 126 {
        frame.push(0x80 | payload.len() as u8);
    } else if payload.len() <= 0xffff {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(&mask_key);
    for (i, b) in payload.iter().enumerate() {
        frame.push(b ^ mask_key[i % 4]);
    }
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_to_ws_url_scheme_mapping() {
        assert_eq!(
            http_to_ws_url("https://example.com/x"),
            "wss://example.com/x"
        );
        assert_eq!(http_to_ws_url("http://example.com/x"), "ws://example.com/x");
        // No scheme -> defaults to wss and strips any leading slashes.
        assert_eq!(http_to_ws_url("example.com/x"), "wss://example.com/x");
        assert_eq!(http_to_ws_url("//example.com"), "wss://example.com");
        assert_eq!(http_to_ws_url("///a"), "wss://a");
    }

    #[test]
    fn preview_truncates_by_characters() {
        assert_eq!(preview("hello", 3), "hel");
        assert_eq!(preview("hi", 10), "hi");
        assert_eq!(preview("", 5), "");
        // Char-based (not byte-based) truncation for multibyte input.
        assert_eq!(preview("héllo", 2), "hé");
    }

    #[test]
    fn encode_short_text_frame_exact_bytes() {
        // FIN+text opcode = 0x81, mask bit + len(2) = 0x82, mask key, then masked payload.
        // 'H'(0x48) ^ 0x37 = 0x7f, 'i'(0x69) ^ 0xfa = 0x93.
        let frame = encode_client_text_frame(b"Hi");
        assert_eq!(frame, vec![0x81, 0x82, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x93]);
    }

    #[test]
    fn encode_empty_frame() {
        let frame = encode_client_text_frame(b"");
        assert_eq!(frame, vec![0x81, 0x80, 0x37, 0xfa, 0x21, 0x3d]);
    }

    #[test]
    fn encode_extended_16bit_length_header() {
        let payload = vec![0u8; 200];
        let frame = encode_client_text_frame(&payload);
        assert_eq!(frame[0], 0x81);
        assert_eq!(frame[1], 0xfe); // 0x80 (mask) | 126 (extended-16 marker)
        assert_eq!(&frame[2..4], &[0x00, 0xc8]); // 200 as big-endian u16
        assert_eq!(&frame[4..8], &[0x37, 0xfa, 0x21, 0x3d]); // mask key
        assert_eq!(frame.len(), 2 + 2 + 4 + 200);
        // Zero payload XORed with the mask reproduces the mask bytes cyclically.
        assert_eq!(frame[8], 0x37);
        assert_eq!(frame[9], 0xfa);
    }
}
