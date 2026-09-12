//! Hard frame-length limits for buffered streams (agent telemetry, log ingest, WS).
//!
//! Unbounded `Stream` / length-prefixed reads let an attacker send an infinite
//! frame and OOM the API process. Every framed reader on the HTTP/agent path
//! must go through [`length_delimited`] or [`constrain_ws`].

use axum::extract::ws::WebSocketUpgrade;
use tokio_util::codec::LengthDelimitedCodec;

/// Default max length-delimited frame (agent log chunks, binary ingest). 1 MiB.
pub const DEFAULT_MAX_STREAM_FRAME_BYTES: usize = 1024 * 1024;
/// Default max WebSocket *message* (assembled frames). 4 MiB.
pub const DEFAULT_MAX_WS_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
/// Default max single WebSocket *frame*. 1 MiB.
pub const DEFAULT_MAX_WS_FRAME_BYTES: usize = 1024 * 1024;

fn clamp_bytes(raw: Option<String>, default: usize, min: usize, max: usize) -> usize {
    raw.and_then(|s| s.trim().parse().ok())
        .filter(|&n| (min..=max).contains(&n))
        .unwrap_or(default)
}

/// Max length-delimited frame. Override with `WEISSMAN_MAX_STREAM_FRAME_BYTES` (4 KiB..=32 MiB).
#[must_use]
pub fn max_stream_frame_bytes() -> usize {
    clamp_bytes(
        std::env::var("WEISSMAN_MAX_STREAM_FRAME_BYTES").ok(),
        DEFAULT_MAX_STREAM_FRAME_BYTES,
        4096,
        32 * 1024 * 1024,
    )
}

/// Max WS message. Override with `WEISSMAN_MAX_WS_MESSAGE_BYTES` (4 KiB..=32 MiB).
#[must_use]
pub fn max_ws_message_bytes() -> usize {
    clamp_bytes(
        std::env::var("WEISSMAN_MAX_WS_MESSAGE_BYTES").ok(),
        DEFAULT_MAX_WS_MESSAGE_BYTES,
        4096,
        32 * 1024 * 1024,
    )
}

/// Max WS frame. Override with `WEISSMAN_MAX_WS_FRAME_BYTES` (4 KiB..=16 MiB).
#[must_use]
pub fn max_ws_frame_bytes() -> usize {
    clamp_bytes(
        std::env::var("WEISSMAN_MAX_WS_FRAME_BYTES").ok(),
        DEFAULT_MAX_WS_FRAME_BYTES,
        4096,
        16 * 1024 * 1024,
    )
}

/// Length-delimited codec with a hard max frame length (4-byte big-endian length prefix).
#[must_use]
pub fn length_delimited() -> LengthDelimitedCodec {
    length_delimited_with_max(max_stream_frame_bytes())
}

/// Length-delimited codec with an explicit max (tests + callers that already resolved the cap).
#[must_use]
pub fn length_delimited_with_max(max_frame_length: usize) -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .max_frame_length(max_frame_length)
        .length_field_length(4)
        .big_endian()
        .new_codec()
}

/// Cap inbound WebSocket frame/message size so a flood cannot pin process RSS.
#[must_use]
pub fn constrain_ws(ws: WebSocketUpgrade) -> WebSocketUpgrade {
    ws.max_message_size(max_ws_message_bytes())
        .max_frame_size(max_ws_frame_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    #[test]
    fn codec_advertises_configured_max() {
        let c = length_delimited_with_max(4096);
        assert_eq!(c.max_frame_length(), 4096);
    }

    #[test]
    fn oversized_frame_is_rejected() {
        // 4-byte length prefix claiming 64 bytes of payload, max allowed 8.
        let mut buf = BytesMut::from(&b"\x00\x00\x00\x40"[..]);
        buf.extend_from_slice(&[0u8; 8]);
        let mut codec = length_delimited_with_max(8);
        let err = codec.decode(&mut buf).expect_err("oversize must fail");
        let msg = err.to_string();
        assert!(
            msg.to_ascii_lowercase().contains("length")
                || msg.to_ascii_lowercase().contains("frame")
                || msg.to_ascii_lowercase().contains("max"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn in_budget_frame_decodes() {
        let mut buf = BytesMut::from(&b"\x00\x00\x00\x04ping"[..]);
        let mut codec = length_delimited_with_max(16);
        let frame = codec.decode(&mut buf).expect("decode").expect("complete");
        assert_eq!(&frame[..], b"ping");
    }
}
