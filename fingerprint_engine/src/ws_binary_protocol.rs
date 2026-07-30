//! Binary WebSocket frame inspection — protobuf wire walk, surgical field mutation, re-encode.

use crate::ws_session::WsConnectOpts;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireType {
    Varint = 0,
    Fixed64 = 1,
    LengthDelimited = 2,
    Fixed32 = 5,
}

#[derive(Clone, Debug)]
pub struct ProtoField {
    pub field_number: u32,
    pub wire_type: WireType,
    pub raw_value: Vec<u8>,
    pub offset: usize,
}

pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, &b) in buf.iter().enumerate() {
        if i >= 10 {
            return None;
        }
        result |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
    }
    None
}

fn encode_varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
    out
}

/// Walk protobuf wire format (no schema required) — deterministic field extraction.
pub fn walk_protobuf_wire(buf: &[u8]) -> Vec<ProtoField> {
    let mut fields = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        let start = i;
        let Some((tag, n)) = decode_varint(&buf[i..]) else {
            break;
        };
        i += n;
        let field_number = (tag >> 3) as u32;
        let wire = match tag & 0x7 {
            0 => WireType::Varint,
            1 => WireType::Fixed64,
            2 => WireType::LengthDelimited,
            5 => WireType::Fixed32,
            _ => break,
        };
        let raw_value = match wire {
            WireType::Varint => {
                let Some((v, vn)) = decode_varint(&buf[i..]) else {
                    break;
                };
                i += vn;
                encode_varint(v)
            }
            WireType::Fixed64 => {
                if i + 8 > buf.len() {
                    break;
                }
                let slice = buf[i..i + 8].to_vec();
                i += 8;
                slice
            }
            WireType::Fixed32 => {
                if i + 4 > buf.len() {
                    break;
                }
                let slice = buf[i..i + 4].to_vec();
                i += 4;
                slice
            }
            WireType::LengthDelimited => {
                let Some((len, ln)) = decode_varint(&buf[i..]) else {
                    break;
                };
                i += ln;
                // `len` is an attacker-supplied u64 varint. `as usize` would truncate on a
                // 32-bit target (2^32 -> 0), silently passing the bound below, so convert
                // checked. `i + len` can also wrap even on 64-bit, so add checked too; bail
                // on either failure or an out-of-range slice.
                let Ok(len) = usize::try_from(len) else {
                    break;
                };
                let Some(end) = i.checked_add(len) else {
                    break;
                };
                if end > buf.len() {
                    break;
                }
                let slice = buf[i..end].to_vec();
                i += len;
                slice
            }
        };
        fields.push(ProtoField {
            field_number,
            wire_type: wire,
            raw_value,
            offset: start,
        });
    }
    fields
}

fn field_tag(field_number: u32, wire: &WireType) -> Vec<u8> {
    let w = match wire {
        WireType::Varint => 0,
        WireType::Fixed64 => 1,
        WireType::LengthDelimited => 2,
        WireType::Fixed32 => 5,
    };
    encode_varint(((field_number << 3) | w) as u64)
}

/// Surgically replace a length-delimited field payload and re-serialize the message.
pub fn mutate_length_delimited_field(
    buf: &[u8],
    target_field: u32,
    new_payload: &[u8],
) -> Option<Vec<u8>> {
    let fields = walk_protobuf_wire(buf);
    if fields.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(buf.len() + new_payload.len());
    let mut replaced = false;
    for f in fields {
        out.extend_from_slice(&field_tag(f.field_number, &f.wire_type));
        if f.field_number == target_field && f.wire_type == WireType::LengthDelimited {
            out.extend_from_slice(&encode_varint(new_payload.len() as u64));
            out.extend_from_slice(new_payload);
            replaced = true;
        } else {
            match f.wire_type {
                WireType::Varint => out.extend_from_slice(&f.raw_value),
                WireType::Fixed64 | WireType::Fixed32 => out.extend_from_slice(&f.raw_value),
                WireType::LengthDelimited => {
                    out.extend_from_slice(&encode_varint(f.raw_value.len() as u64));
                    out.extend_from_slice(&f.raw_value);
                }
            }
        }
    }
    if replaced {
        Some(out)
    } else {
        None
    }
}

/// Heuristic: pick string fields that look like role/amount/id flags for mutation.
pub fn pick_mutable_string_fields(fields: &[ProtoField]) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    for f in fields {
        if f.wire_type != WireType::LengthDelimited {
            continue;
        }
        if let Ok(s) = std::str::from_utf8(&f.raw_value) {
            let l = s.to_ascii_lowercase();
            if l.contains("user")
                || l.contains("admin")
                || l.contains("role")
                || l.chars().all(|c| c.is_ascii_digit())
            {
                out.push((f.field_number, s.to_string()));
            }
        }
    }
    out
}

#[derive(Clone, Debug, Default)]
pub struct BinaryProbeResult {
    pub sent_len: usize,
    pub reply_text: Vec<String>,
    pub reply_binary: Vec<Vec<u8>>,
    pub protobuf_parsed: bool,
    pub mutation_transmitted: bool,
    pub server_processed_binary: bool,
}

/// Decode binary server reply; mutate first protobuf string field; transmit manipulated frame.
pub async fn binary_mutation_probe(
    http_url: &str,
    opts: &WsConnectOpts,
    seed_binary: &[u8],
) -> Option<BinaryProbeResult> {
    let mut result = BinaryProbeResult {
        sent_len: seed_binary.len(),
        ..Default::default()
    };

    let fields = walk_protobuf_wire(seed_binary);
    result.protobuf_parsed = !fields.is_empty();

    let mut outbound_binary = vec![seed_binary.to_vec()];
    if let Some((field_num, original)) = pick_mutable_string_fields(&fields).into_iter().next() {
        let mut mutated = original.clone();
        if original.chars().all(|c| c.is_ascii_digit()) {
            mutated = "1".to_string();
        } else if original.to_ascii_lowercase().contains("user") {
            mutated = "administrator".to_string();
        } else {
            mutated.push_str("_weissman_probe");
        }
        if let Some(reencoded) =
            mutate_length_delimited_field(seed_binary, field_num, mutated.as_bytes())
        {
            outbound_binary.push(reencoded);
            result.mutation_transmitted = true;
        }
    } else {
        outbound_binary.push(seed_binary.to_vec());
    }

    let ex = crate::ws_session::exchange_frames(http_url, opts, &[], &outbound_binary).await?;
    let has_text = !ex.received.is_empty();
    let has_bin = ex.received_binary.iter().any(|b| !b.is_empty());
    result.server_processed_binary = has_text || has_bin;
    result.reply_text = ex.received;
    result.reply_binary = ex.received_binary;

    Some(result)
}

/// Build a minimal protobuf-like binary seed (field 1 string + field 2 varint) for gateways without schema.
pub fn synthetic_protobuf_seed(role: &str, amount: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&field_tag(1, &WireType::LengthDelimited));
    out.extend_from_slice(&encode_varint(role.len() as u64));
    out.extend_from_slice(role.as_bytes());
    out.extend_from_slice(&field_tag(2, &WireType::Varint));
    out.extend_from_slice(&encode_varint(amount));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_protobuf_walk() {
        let seed = synthetic_protobuf_seed("user", 100);
        let fields = walk_protobuf_wire(&seed);
        assert!(fields.len() >= 2);
    }

    #[test]
    fn mutates_length_delimited_field() {
        let seed = synthetic_protobuf_seed("user", 100);
        let mutated = mutate_length_delimited_field(&seed, 1, b"administrator").unwrap();
        assert_ne!(seed, mutated);
        let fields = walk_protobuf_wire(&mutated);
        let s = fields
            .iter()
            .find(|f| f.field_number == 1)
            .map(|f| String::from_utf8_lossy(&f.raw_value).to_string());
        assert_eq!(s.as_deref(), Some("administrator"));
    }

    #[test]
    fn client_text_frame_non_empty() {
        use crate::ws_session::encode_client_text_frame;
        let f = encode_client_text_frame(b"probe");
        assert!(f.len() > 5);
    }
}
