//! Opt-in PLC decoy listener (Modbus 502 / S7 102).
//!
//! Armed only when `WEISSMAN_OT_PLC_DECOY=1`. Binds loopback by default so a
//! plant NIC is never hijacked by accident. Replies look like a PLC; writes
//! get exception 0x01. Every accepted connection is a finding for SOAR.

use super::finding;
use serde_json::{json, Map, Value};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

static DECOY_HITS: AtomicU64 = AtomicU64::new(0);

pub fn decoy_enabled() -> bool {
    std::env::var("WEISSMAN_OT_PLC_DECOY")
        .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn spawn() {
    if !decoy_enabled() {
        return;
    }
    let bind = std::env::var("WEISSMAN_OT_PLC_DECOY_BIND").unwrap_or_else(|_| "127.0.0.1".into());
    tokio::spawn(listen_port(bind.clone(), 502));
    tokio::spawn(listen_port(bind, 102));
}

async fn listen_port(host: String, port: u16) {
    let addr = format!("{host}:{port}");
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!(target: "agent.ot_decoy", port, error = %e, "PLC decoy bind failed");
            return;
        }
    };
    info!(target: "agent.ot_decoy", %addr, "PLC decoy armed");
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                tokio::spawn(handle(stream, peer, port));
            }
            Err(e) => {
                warn!(target: "agent.ot_decoy", error = %e, "accept failed");
            }
        }
    }
}

async fn handle(mut stream: TcpStream, peer: SocketAddr, port: u16) {
    let mut buf = [0u8; 512];
    let n = match stream.read(&mut buf).await {
        Ok(0) | Err(_) => return,
        Ok(n) => n,
    };
    if let Some(reply) = decoy_reply(port, &buf[..n]) {
        let _ = stream.write_all(&reply).await;
        let _ = stream.shutdown().await;
    }
    let hits = DECOY_HITS.fetch_add(1, Ordering::Relaxed) + 1;
    info!(
        target: "agent.ot_decoy",
        peer = %peer,
        port,
        bytes = n,
        hits,
        "decoy served bait — record in SOAR, production PLC untouched"
    );
}

#[must_use]
pub fn decoy_reply(port: u16, request: &[u8]) -> Option<Vec<u8>> {
    match port {
        502 => decoy_modbus(request),
        102 => decoy_s7_cc(request),
        _ => None,
    }
}

fn decoy_modbus(request: &[u8]) -> Option<Vec<u8>> {
    if request.len() < 8 {
        return None;
    }
    let tx = u16::from_be_bytes([request[0], request[1]]);
    let unit = request[6];
    let fc = request[7] & 0x7f;
    match fc {
        0x03 | 0x04 => Some(wrap_mbap(tx, unit, &[fc, 0x02, 0x00, 0x2A])),
        0x01 | 0x02 => Some(wrap_mbap(tx, unit, &[fc, 0x01, 0x01])),
        _ => Some(wrap_mbap(tx, unit, &[fc | 0x80, 0x01])),
    }
}

fn wrap_mbap(tx: u16, unit: u8, pdu: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(7 + pdu.len());
    f.extend_from_slice(&tx.to_be_bytes());
    f.extend_from_slice(&[0x00, 0x00]);
    let length = u16::try_from(pdu.len() + 1).unwrap_or(1);
    f.extend_from_slice(&length.to_be_bytes());
    f.push(unit);
    f.extend_from_slice(pdu);
    f
}

fn decoy_s7_cc(request: &[u8]) -> Option<Vec<u8>> {
    if request.len() < 6 || request[5] != 0xe0 {
        return None;
    }
    Some(vec![
        0x03, 0x00, 0x00, 0x16, 0x11, 0xd0, 0x00, 0x01, 0x00, 0x01, 0x00, 0xc1, 0x02, 0x01, 0x00,
        0xc2, 0x02, 0x01, 0x00, 0xc0, 0x01, 0x09,
    ])
}

pub async fn run(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut extras = Map::new();
    extras.insert("enabled".into(), json!(decoy_enabled()));
    extras.insert("ports".into(), json!([502, 102]));
    extras.insert("bind_default".into(), json!("127.0.0.1"));
    extras.insert("writes_honoured".into(), json!(false));
    extras.insert("hits".into(), json!(DECOY_HITS.load(Ordering::Relaxed)));
    Ok(vec![finding(
        engine,
        if decoy_enabled() {
            "OT PLC decoy armed (Modbus 502 / S7 102) — bait only, writes refused"
        } else {
            "OT PLC decoy idle (set WEISSMAN_OT_PLC_DECOY=1 to listen on loopback)"
        },
        "info",
        "T0843",
        "Dynamic PLC honeypot: canned FC03/COTP CC for scanners. Production process image is never bound.",
        extras,
    )])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_gets_register_write_gets_exception() {
        let read = {
            let mut f = vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03];
            f.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
            f
        };
        let r = decoy_reply(502, &read).unwrap();
        assert_eq!(r[7], 0x03);
        let write = vec![
            0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x00, 0x00, 0x01,
        ];
        let w = decoy_reply(502, &write).unwrap();
        assert_eq!(w[7], 0x86);
        assert_eq!(w[8], 0x01);
    }
}
