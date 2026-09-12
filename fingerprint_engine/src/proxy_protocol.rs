//! PROXY protocol v2 preface on the Axum TCP listener.
//!
//! Stock nginx `http { proxy_pass }` cannot emit PROXY v2. Use the stream snippet
//! in `deploy/nginx-stream-proxy-protocol.conf` with `WEISSMAN_PROXY_PROTOCOL=1`.
//! Optional TLV 0xE0 carries raw TLS ClientHello bytes when the terminator can
//! attach them. JA3/JA4 still prefer `X-SSL-Client-Hello` from OpenResty.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Experimental PROXY v2 TLV: raw TLS ClientHello (Weissman honey-routing).
pub const TLV_CLIENT_HELLO: u8 = 0xE0;

const V2_SIG: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

#[derive(Debug, Clone, Default)]
pub struct ProxyPreface {
    pub source: Option<SocketAddr>,
    pub client_hello: Option<Vec<u8>>,
}

#[must_use]
pub fn enabled() -> bool {
    matches!(
        std::env::var("WEISSMAN_PROXY_PROTOCOL").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

/// If the stream starts with PROXY v2, consume the header and return source + optional hello.
pub async fn maybe_read(
    mut stream: TcpStream,
    peer: SocketAddr,
) -> std::io::Result<(TcpStream, SocketAddr, Option<Vec<u8>>)> {
    if !enabled() {
        return Ok((stream, peer, None));
    }
    let mut sig = [0u8; 12];
    let n = stream.peek(&mut sig).await?;
    if n < 12 || &sig != V2_SIG {
        return Ok((stream, peer, None));
    }
    let mut head = [0u8; 16];
    stream.read_exact(&mut head).await?;
    let len = u16::from_be_bytes([head[14], head[15]]) as usize;
    let mut rest = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut rest).await?;
    }
    let parsed = parse_v2_body(&head, &rest).unwrap_or_default();
    let addr = parsed.source.unwrap_or(peer);
    Ok((stream, addr, parsed.client_hello))
}

/// Parse PROXY v2 header (16-byte block + address/TLV body). Used by tests and the listener.
#[must_use]
pub fn parse_v2_body(head: &[u8], body: &[u8]) -> Option<ProxyPreface> {
    if head.len() < 16 || &head[..12] != V2_SIG {
        return None;
    }
    let ver_cmd = head[12];
    if ver_cmd >> 4 != 0x2 {
        return None;
    }
    let fam = head[13];
    let mut i = 0;
    let mut source = None;
    match fam {
        0x11 if body.len() >= 12 => {
            // TCPv4
            let ip = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            let port = u16::from_be_bytes([body[8], body[9]]);
            source = Some(SocketAddr::new(IpAddr::V4(ip), port));
            i = 12;
        }
        0x21 if body.len() >= 36 => {
            let mut oct = [0u8; 16];
            oct.copy_from_slice(&body[..16]);
            let port = u16::from_be_bytes([body[32], body[33]]);
            source = Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(oct)), port));
            i = 36;
        }
        _ => {}
    }
    let mut client_hello = None;
    while i + 3 <= body.len() {
        let tlv_type = body[i];
        let tlv_len = u16::from_be_bytes([body[i + 1], body[i + 2]]) as usize;
        i += 3;
        if i + tlv_len > body.len() {
            break;
        }
        if tlv_type == TLV_CLIENT_HELLO {
            client_hello = Some(body[i..i + tlv_len].to_vec());
        }
        i += tlv_len;
    }
    Some(ProxyPreface {
        source,
        client_hello,
    })
}

/// Write a v2 TCP4 header (tests / local injectors).
pub fn encode_v2_tcp4(src: SocketAddr, dst: SocketAddr, hello: Option<&[u8]>) -> Vec<u8> {
    let mut body = Vec::new();
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            body.extend_from_slice(&s.octets());
            body.extend_from_slice(&d.octets());
            body.extend_from_slice(&src.port().to_be_bytes());
            body.extend_from_slice(&dst.port().to_be_bytes());
        }
        _ => {}
    }
    if let Some(h) = hello {
        body.push(TLV_CLIENT_HELLO);
        let len = (h.len() as u16).to_be_bytes();
        body.extend_from_slice(&len);
        body.extend_from_slice(h);
    }
    let mut out = Vec::from(*V2_SIG);
    out.push(0x21); // v2 PROXY
    out.push(0x11); // TCP4
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend(body);
    out
}

/// Prefix a live stream with PROXY v2 (dev inject only — not used in production paths).
pub async fn write_v2<W: AsyncWriteExt + Unpin>(w: &mut W, bytes: &[u8]) -> std::io::Result<()> {
    w.write_all(bytes).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_tcp4_with_hello() {
        let src: SocketAddr = "198.51.100.7:44443".parse().unwrap();
        let dst: SocketAddr = "10.0.0.1:8000".parse().unwrap();
        let hello = b"\x01\x00\x00\x04test";
        let pkt = encode_v2_tcp4(src, dst, Some(hello));
        let head = &pkt[..16];
        let body = &pkt[16..];
        let p = parse_v2_body(head, body).unwrap();
        assert_eq!(p.source, Some(src));
        assert_eq!(p.client_hello.as_deref(), Some(hello.as_slice()));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_v2_body(&[0; 16], &[]).is_none());
    }
}
