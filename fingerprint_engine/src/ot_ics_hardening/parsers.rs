//! Streaming OT protocol parsers (nom + bounded COTP assembly + iterative BER).
//!
//! Every public parse function:
//! * never panics on truncated / hostile input
//! * maps headers onto `&[u8]` (zero-copy) except COTP DT reassembly, which uses
//!   a pre-allocated 8 KiB buffer so ISO 8073 fragments can be joined
//! * walks BER/MMS iteratively on a 16-slot inline node array (heap only on spill)
//! * rejects length fields that disagree with the physical buffer (OOB)
//!
//! `unsafe_code` is denied crate-wide — zero-copy is `&[u8]` slicing, not `ptr::copy`.

use nom::error::{ContextError, ErrorKind, ParseError};
use nom::number::{be_u16, be_u8, le_u16};
use nom::{Err as NomErr, IResult, Parser};
use serde::Serialize;
use std::time::{Duration, Instant};

/// Context-carrying nom error so weissman-server logs a binary-accurate decode failure.
#[derive(Debug, Clone)]
pub struct OtNomError<I> {
    pub input: I,
    pub contexts: Vec<&'static str>,
    pub kind: ErrorKind,
}

impl<I> ParseError<I> for OtNomError<I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        Self {
            input,
            contexts: Vec::new(),
            kind,
        }
    }
    fn append(input: I, kind: ErrorKind, mut other: Self) -> Self {
        other.input = input;
        other.kind = kind;
        other
    }
}

impl<I> ContextError<I> for OtNomError<I> {
    fn add_context(_input: I, ctx: &'static str, mut other: Self) -> Self {
        other.contexts.push(ctx);
        other
    }
}

pub type OtParseError<'a> = OtNomError<&'a [u8]>;
pub type OtIResult<'a, T> = IResult<&'a [u8], T, OtParseError<'a>>;

fn fail<'a>(i: &'a [u8], ctx: &'static str) -> NomErr<OtParseError<'a>> {
    NomErr::Failure(OtNomError {
        input: i,
        contexts: vec![ctx],
        kind: ErrorKind::Fail,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseFail {
    pub context: String,
    pub kind: String,
    pub remaining_len: usize,
}

impl ParseFail {
    fn from_nom(err: NomErr<OtParseError<'_>>) -> Self {
        match err {
            NomErr::Incomplete(n) => Self {
                context: "incomplete".into(),
                kind: format!("{n:?}"),
                remaining_len: 0,
            },
            NomErr::Error(e) | NomErr::Failure(e) => {
                let kind = e
                    .contexts
                    .last()
                    .copied()
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("{:?}", e.kind));
                Self {
                    context: kind.clone(),
                    kind,
                    remaining_len: e.input.len(),
                }
            }
        }
    }
}

// ── Modbus TCP ───────────────────────────────────────────────────────────────

/// MBAP header is 7 bytes: tx(2) proto(2) length(2) unit(1). `#[repr(C)]` documents
/// on-wire layout; we never transmute — fields are copied from nom.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MbapHeader {
    pub transaction_id: u16,
    pub protocol_id: u16,
    pub length: u16,
    pub unit_id: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ModbusPdu<'a> {
    pub function: u8,
    pub exception: bool,
    pub exception_code: Option<u8>,
    pub data: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ModbusFrame<'a> {
    pub header: MbapHeader,
    pub pdu: ModbusPdu<'a>,
}

/// Parse MBAP independently of the PDU (spec MB-11 / Part5-11).
pub fn parse_mbap(input: &[u8]) -> OtIResult<'_, MbapHeader> {
    let (i, transaction_id) = be_u16().parse(input)?;
    let (i, protocol_id) = be_u16().parse(i)?;
    let (i, length) = be_u16().parse(i)?;
    let (i, unit_id) = be_u8().parse(i)?;
    if protocol_id != 0 {
        return Err(fail(i, "protocol_id_nonzero"));
    }
    if length < 1 || length > 254 {
        return Err(fail(i, "mbap_length_oob"));
    }
    // Length counts unit-id (already consumed) + PDU. Remaining must be ≥ length-1.
    let pdu_len = (length as usize).saturating_sub(1);
    if i.len() < pdu_len {
        return Err(fail(i, "mbap_length_vs_buffer"));
    }
    Ok((
        i,
        MbapHeader {
            transaction_id,
            protocol_id,
            length,
            unit_id,
        },
    ))
}

pub fn parse_modbus_pdu(input: &[u8]) -> OtIResult<'_, ModbusPdu<'_>> {
    let (i, function) = be_u8().parse(input)?;
    let exception = function & 0x80 != 0;
    if exception {
        let (i, code) = be_u8().parse(i)?;
        Ok((
            i,
            ModbusPdu {
                function,
                exception: true,
                exception_code: Some(code),
                data: i,
            },
        ))
    } else {
        Ok((
            &[],
            ModbusPdu {
                function,
                exception: false,
                exception_code: None,
                data: i,
            },
        ))
    }
}

pub fn parse_modbus_frame(input: &[u8]) -> Result<ModbusFrame<'_>, ParseFail> {
    let (rest, header) = parse_mbap(input).map_err(ParseFail::from_nom)?;
    let pdu_len = (header.length as usize).saturating_sub(1);
    let pdu_bytes = rest.get(..pdu_len).ok_or_else(|| ParseFail {
        context: "pdu_slice".into(),
        kind: "mbap_length_vs_buffer".into(),
        remaining_len: rest.len(),
    })?;
    let (_, pdu) = parse_modbus_pdu(pdu_bytes).map_err(ParseFail::from_nom)?;
    Ok(ModbusFrame { header, pdu })
}

/// Optional Modbus RTU CRC-16 (poly 0xA001) when traffic is serial-bridged.
#[must_use]
pub fn modbus_rtu_crc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= u16::from(b);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

#[must_use]
pub fn sanitize_register_u16(raw: u16, lo: u16, hi: u16) -> Option<u16> {
    if raw < lo || raw > hi {
        None
    } else {
        Some(raw)
    }
}

#[must_use]
pub fn is_gateway_unit(unit_id: u8) -> bool {
    // Unit 0 is broadcast; 247–255 commonly map through serial gateways.
    unit_id == 0 || unit_id >= 247
}

#[must_use]
pub fn modbus_exception_meaning(code: u8) -> &'static str {
    match code {
        0x01 => "illegal_function",
        0x02 => "illegal_data_address",
        0x03 => "illegal_data_value",
        0x04 => "slave_device_failure",
        0x05 => "acknowledge",
        0x06 => "slave_device_busy",
        0x08 => "memory_parity_error",
        0x0a => "gateway_path_unavailable",
        0x0b => "gateway_target_device_failed_to_respond",
        _ => "unknown_exception_code",
    }
}

// ── Siemens S7 / ISO-on-TCP (RFC 1006 + ISO 8073) ────────────────────────────

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TpktHeader {
    pub version: u8,
    pub reserved: u8,
    pub length: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CotpHeader {
    pub li: u8,
    pub pdu_type: u8,
    pub dst_ref: u16,
    pub src_ref: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct S7Header {
    pub protocol_id: u8,
    pub rosctr: u8,
    pub pdu_ref: u16,
    pub param_len: u16,
    pub data_len: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct S7Frame<'a> {
    pub tpkt: TpktHeader,
    pub cotp: CotpHeader,
    pub s7: Option<S7Header>,
    pub userdata: &'a [u8],
}

pub fn parse_tpkt(input: &[u8]) -> OtIResult<'_, TpktHeader> {
    let (i, version) = be_u8().parse(input)?;
    let (i, reserved) = be_u8().parse(i)?;
    let (i, length) = be_u16().parse(i)?;
    if version != 0x03 {
        return Err(fail(i, "tpkt_version"));
    }
    if reserved != 0 {
        return Err(fail(i, "tpkt_reserved"));
    }
    if length < 7 || usize::from(length) > input.len() {
        return Err(fail(i, "tpkt_length"));
    }
    let need = usize::from(length).saturating_sub(4);
    if i.len() < need {
        return Err(fail(i, "tpkt_length_vs_buffer"));
    }
    Ok((
        i,
        TpktHeader {
            version,
            reserved,
            length,
        },
    ))
}

pub fn parse_cotp(input: &[u8]) -> OtIResult<'_, CotpHeader> {
    let (i, li) = be_u8().parse(input)?;
    let (i, pdu_type) = be_u8().parse(i)?;
    if li < 2 {
        return Err(fail(i, "cotp_li"));
    }
    // CR/CC carry src/dst refs; DT may be shorter.
    let (i, dst_ref, src_ref) = if i.len() >= 4 && (pdu_type == 0xe0 || pdu_type == 0xd0) {
        let (i, d) = be_u16().parse(i)?;
        let (i, s) = be_u16().parse(i)?;
        (i, d, s)
    } else {
        (i, 0, 0)
    };
    Ok((
        i,
        CotpHeader {
            li,
            pdu_type,
            dst_ref,
            src_ref,
        },
    ))
}

pub fn parse_s7_header(input: &[u8]) -> OtIResult<'_, S7Header> {
    let (i, protocol_id) = be_u8().parse(input)?;
    if protocol_id != 0x32 {
        return Err(fail(i, "s7_protocol_id"));
    }
    let (i, rosctr) = be_u8().parse(i)?;
    let (i, _redundancy) = be_u16().parse(i)?;
    let (i, pdu_ref) = be_u16().parse(i)?;
    let (i, param_len) = be_u16().parse(i)?;
    let (i, data_len) = be_u16().parse(i)?;
    let need = param_len as usize + data_len as usize;
    if i.len() < need {
        return Err(fail(i, "s7_pdu_overread"));
    }
    Ok((
        i,
        S7Header {
            protocol_id,
            rosctr,
            pdu_ref,
            param_len,
            data_len,
        },
    ))
}

pub fn parse_s7_iso_on_tcp(input: &[u8]) -> Result<S7Frame<'_>, ParseFail> {
    if input.len() < 7 {
        return Err(ParseFail {
            context: "s7_iso".into(),
            kind: "truncated".into(),
            remaining_len: input.len(),
        });
    }
    let (after_tpkt, tpkt) = parse_tpkt(input).map_err(ParseFail::from_nom)?;
    if usize::from(tpkt.length) != input.len() && usize::from(tpkt.length) > input.len() {
        return Err(ParseFail {
            context: "tpkt".into(),
            kind: "tpkt_length_vs_buffer".into(),
            remaining_len: input.len(),
        });
    }
    let (after_cotp, cotp) = parse_cotp(after_tpkt).map_err(ParseFail::from_nom)?;
    let s7 = parse_s7_header(after_cotp).ok().map(|(_, h)| h);
    Ok(S7Frame {
        tpkt,
        cotp,
        s7,
        userdata: after_cotp,
    })
}

/// Pre-allocated COTP DT reassembly. ISO 8073 may split one S7 PDU across TPDUs;
/// zero-copy slices cannot join them. Cap is 8 KiB (S7-1500 negotiated max).
pub const COTP_ASSEMBLY_CAP: usize = 8192;
/// Inter-fragment timeout — incomplete TPDUs are dropped (industrial Slowloris).
pub const MAX_COTP_FRAGMENT_TIMEOUT: Duration = Duration::from_millis(50);

#[derive(Debug)]
pub struct CotpAssembler {
    buf: Vec<u8>,
    last_cotp: Option<CotpHeader>,
    last_tpkt: Option<TpktHeader>,
    fragments: u32,
    last_frag: Option<Instant>,
}

impl Default for CotpAssembler {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct AssembledCotp {
    pub tpkt: TpktHeader,
    pub cotp: CotpHeader,
    pub userdata: Vec<u8>,
    pub fragments: u32,
}

impl CotpAssembler {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(256),
            last_cotp: None,
            last_tpkt: None,
            fragments: 0,
            last_frag: None,
        }
    }

    pub fn reset(&mut self) {
        self.buf.clear();
        self.fragments = 0;
        self.last_frag = None;
        self.last_cotp = None;
        self.last_tpkt = None;
    }

    #[must_use]
    pub fn timed_out(&self) -> bool {
        self.last_frag
            .map(|t| t.elapsed() > MAX_COTP_FRAGMENT_TIMEOUT)
            .unwrap_or(false)
    }

    /// Feed one TPKT. `Ok(Some)` when the TPDU is complete (CR/CC, or DT with EOT).
    pub fn push(&mut self, packet: &[u8]) -> Result<Option<AssembledCotp>, ParseFail> {
        if packet.len() < 7 {
            return Err(ParseFail {
                context: "cotp_asm".into(),
                kind: "truncated".into(),
                remaining_len: packet.len(),
            });
        }
        let now = Instant::now();
        if let Some(last) = self.last_frag {
            if now.duration_since(last) > MAX_COTP_FRAGMENT_TIMEOUT {
                self.reset();
                return Err(ParseFail {
                    context: "cotp_asm".into(),
                    kind: "fragment_timeout".into(),
                    remaining_len: packet.len(),
                });
            }
        }
        self.last_frag = Some(now);

        let (after_tpkt, tpkt) = parse_tpkt(packet).map_err(ParseFail::from_nom)?;
        let (after_cotp, cotp) = parse_cotp(after_tpkt).map_err(ParseFail::from_nom)?;
        self.last_tpkt = Some(tpkt);
        self.last_cotp = Some(cotp);
        self.fragments = self.fragments.saturating_add(1);

        if cotp.pdu_type == 0xf0 {
            let (eot, payload) = cotp_dt_payload(after_cotp)?;
            if self.buf.len().saturating_add(payload.len()) > COTP_ASSEMBLY_CAP {
                self.reset();
                return Err(ParseFail {
                    context: "cotp_asm".into(),
                    kind: "assembly_overflow".into(),
                    remaining_len: payload.len(),
                });
            }
            self.buf.extend_from_slice(payload);
            if eot {
                return Ok(Some(self.take()));
            }
            return Ok(None);
        }

        // CR/CC/other: no DT fragmentation.
        self.buf.clear();
        self.buf.extend_from_slice(after_cotp);
        Ok(Some(self.take()))
    }

    fn take(&mut self) -> AssembledCotp {
        let out = AssembledCotp {
            tpkt: self.last_tpkt.unwrap_or(TpktHeader {
                version: 3,
                reserved: 0,
                length: 0,
            }),
            cotp: self.last_cotp.unwrap_or(CotpHeader {
                li: 0,
                pdu_type: 0,
                dst_ref: 0,
                src_ref: 0,
            }),
            userdata: std::mem::take(&mut self.buf),
            fragments: self.fragments,
        };
        self.reset();
        out
    }
}

fn cotp_dt_payload(after_type: &[u8]) -> Result<(bool, &[u8]), ParseFail> {
    let nr_eot = *after_type.first().ok_or(ParseFail {
        context: "cotp_dt".into(),
        kind: "truncated_eot".into(),
        remaining_len: 0,
    })?;
    Ok((nr_eot & 0x80 != 0, after_type.get(1..).unwrap_or(&[])))
}

pub fn cotp_is_cc(pdu_type: u8) -> bool {
    pdu_type == 0xd0 || pdu_type == 0xd6
}

pub fn s7_observed_cpu_control(userdata: &[u8]) -> bool {
    userdata.windows(2).any(|w| w[0] == 0x32 && w[1] == 0x05)
        || (userdata.first() == Some(&0x32)
            && userdata.get(1) == Some(&0x07)
            && userdata.iter().any(|b| *b == 0x05))
}

// ── DNP3 (IEEE 1815) ─────────────────────────────────────────────────────────

/// DNP3 CRC-16 (reflected poly 0xA6BC). Applied per 16-byte data-link block.
#[must_use]
pub fn dnp3_crc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= u16::from(b);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xA6BC;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Dnp3LinkHeader {
    pub start1: u8,
    pub start2: u8,
    pub length: u8,
    pub control: u8,
    pub dest: u16,
    pub src: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Dnp3Iin {
    pub iin1: u8,
    pub iin2: u8,
}

impl Dnp3Iin {
    #[must_use]
    pub fn hardware_trouble(self) -> bool {
        self.iin1 & 0x40 != 0 || self.iin2 & 0x01 != 0
    }
    #[must_use]
    pub fn config_corrupt(self) -> bool {
        self.iin2 & 0x02 != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Dnp3Frame<'a> {
    pub link: Dnp3LinkHeader,
    pub transport_fir: bool,
    pub transport_fin: bool,
    pub transport_seq: u8,
    pub app_fc: Option<u8>,
    pub iin: Option<Dnp3Iin>,
    pub payload: &'a [u8],
}

pub fn parse_dnp3_link(input: &[u8]) -> Result<Dnp3Frame<'_>, ParseFail> {
    if input.len() < 10 {
        return Err(ParseFail {
            context: "dnp3_link".into(),
            kind: "truncated".into(),
            remaining_len: input.len(),
        });
    }
    let (_, hdr) = (|| -> OtIResult<'_, Dnp3LinkHeader> {
        let (i, start1) = be_u8().parse(input)?;
        let (i, start2) = be_u8().parse(i)?;
        if start1 != 0x05 || start2 != 0x64 {
            return Err(fail(i, "dnp3_start_bytes"));
        }
        let (i, length) = be_u8().parse(i)?;
        let (i, control) = be_u8().parse(i)?;
        let (i, dest) = le_u16().parse(i)?;
        let (i, src) = le_u16().parse(i)?;
        Ok((
            i,
            Dnp3LinkHeader {
                start1,
                start2,
                length,
                control,
                dest,
                src,
            },
        ))
    })()
    .map_err(ParseFail::from_nom)?;

    // Header CRC covers the 8 bytes after start? Spec: CRC over bytes 0..7 (start through src).
    let header_bytes = input.get(..8).ok_or_else(|| ParseFail {
        context: "dnp3_crc".into(),
        kind: "truncated".into(),
        remaining_len: input.len(),
    })?;
    let crc_bytes = input.get(8..10).ok_or_else(|| ParseFail {
        context: "dnp3_crc".into(),
        kind: "truncated".into(),
        remaining_len: input.len(),
    })?;
    let claimed = u16::from_le_bytes([crc_bytes[0], crc_bytes[1]]);
    let calc = dnp3_crc(header_bytes);
    if claimed != calc {
        return Err(ParseFail {
            context: "dnp3_crc".into(),
            kind: "link_crc_mismatch".into(),
            remaining_len: input.len(),
        });
    }

    let user_len = hdr.length.saturating_sub(5) as usize; // length = control+dest+src+userdata
    let rest = input.get(10..).unwrap_or(&[]);
    // User data is chunked into 16-byte blocks each followed by 2-byte CRC.
    let mut assembled: Vec<u8> = Vec::new();
    let mut cursor = 0usize;
    let mut remaining = user_len;
    while remaining > 0 {
        let take = remaining.min(16);
        let block = rest.get(cursor..cursor + take).ok_or_else(|| ParseFail {
            context: "dnp3_block".into(),
            kind: "truncated_user_data".into(),
            remaining_len: rest.len().saturating_sub(cursor),
        })?;
        let crc_off = cursor + take;
        let bcrc = rest.get(crc_off..crc_off + 2).ok_or_else(|| ParseFail {
            context: "dnp3_block_crc".into(),
            kind: "truncated_block_crc".into(),
            remaining_len: rest.len().saturating_sub(crc_off),
        })?;
        let claimed_b = u16::from_le_bytes([bcrc[0], bcrc[1]]);
        if dnp3_crc(block) != claimed_b {
            return Err(ParseFail {
                context: "dnp3_block_crc".into(),
                kind: "user_crc_mismatch".into(),
                remaining_len: remaining,
            });
        }
        assembled.extend_from_slice(block);
        cursor = crc_off + 2;
        remaining -= take;
    }

    let (tfir, tfin, tseq, app_fc, iin, payload_off) = if assembled.is_empty() {
        (false, false, 0u8, None, None, 0usize)
    } else {
        let th = assembled[0];
        let fir = th & 0x80 != 0;
        let fin = th & 0x40 != 0;
        let seq = th & 0x3f;
        let app = assembled.get(1).copied();
        let iin = if assembled.len() >= 4 {
            Some(Dnp3Iin {
                iin1: assembled[2],
                iin2: assembled[3],
            })
        } else {
            None
        };
        (fir, fin, seq, app, iin, 1usize)
    };

    // Payload is assembled user data; we keep a slice of the *original* buffer after
    // the link header for zero-copy callers, plus parsed transport fields.
    let payload = input.get(10..).unwrap_or(&[]);
    let _ = payload_off;
    Ok(Dnp3Frame {
        link: hdr,
        transport_fir: tfir,
        transport_fin: tfin,
        transport_seq: tseq,
        app_fc,
        iin,
        payload,
    })
}

/// Recursively walk DNP3 object headers with a hard depth cap (spec DNP-03).
pub fn walk_dnp3_objects(payload: &[u8], max_depth: u32) -> Result<Vec<(u8, u8)>, ParseFail> {
    walk_dnp3_objects_inner(payload, max_depth, 0)
}

fn walk_dnp3_objects_inner(
    payload: &[u8],
    max_depth: u32,
    depth: u32,
) -> Result<Vec<(u8, u8)>, ParseFail> {
    if depth >= max_depth {
        return Err(ParseFail {
            context: "dnp3_objects".into(),
            kind: "max_depth".into(),
            remaining_len: payload.len(),
        });
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut guard = 0u32;
    while i + 3 <= payload.len() && guard < 64 {
        guard += 1;
        let group = payload[i];
        let variation = payload[i + 1];
        let qualifier = payload[i + 2];
        if group == 70 {
            return Err(ParseFail {
                context: "dnp3_objects".into(),
                kind: "file_transfer_group".into(),
                remaining_len: payload.len() - i,
            });
        }
        out.push((group, variation));
        // Qualifier 0x00/0x01: packed 8-bit start/stop — skip 2 bytes if present.
        i += 3;
        if qualifier <= 0x06 && i + 2 <= payload.len() {
            i += 2;
        }
        if group == 0 && variation == 0 {
            break;
        }
    }
    Ok(out)
}

// ── IEC 61850 GOOSE / SV / MMS BER ───────────────────────────────────────────

pub const GOOSE_ETHERTYPE: u16 = 0x88B8;
pub const SV_ETHERTYPE: u16 = 0x88BA;
pub const VLAN_ETHERTYPE: u16 = 0x8100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EthernetHeader {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
    pub vlan: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GooseHeader {
    pub appid: u16,
    pub length: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GooseFrame<'a> {
    pub eth: EthernetHeader,
    pub goose: GooseHeader,
    pub st_num: Option<u32>,
    pub sq_num: Option<u32>,
    pub simulation: bool,
    pub time_allowed_to_live: Option<u32>,
    pub apdu: &'a [u8],
}

pub fn parse_ethernet(input: &[u8]) -> Result<(EthernetHeader, &[u8]), ParseFail> {
    if input.len() < 14 {
        return Err(ParseFail {
            context: "ethernet".into(),
            kind: "truncated".into(),
            remaining_len: input.len(),
        });
    }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&input[0..6]);
    src.copy_from_slice(&input[6..12]);
    let mut off = 12usize;
    let mut et = u16::from_be_bytes([input[off], input[off + 1]]);
    off += 2;
    let mut vlan = None;
    if et == VLAN_ETHERTYPE {
        if input.len() < off + 4 {
            return Err(ParseFail {
                context: "ethernet".into(),
                kind: "truncated_vlan".into(),
                remaining_len: input.len(),
            });
        }
        vlan = Some(u16::from_be_bytes([input[off], input[off + 1]]));
        off += 2;
        et = u16::from_be_bytes([input[off], input[off + 1]]);
        off += 2;
    }
    Ok((
        EthernetHeader {
            dst,
            src,
            ethertype: et,
            vlan,
        },
        &input[off..],
    ))
}

/// Single-level BER TLV (no recursion). Nested MMS/GOOSE uses [`walk_ber_iterative`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BerTlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
}

/// Heap-stack node from the iterative BER walker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BerNode {
    pub tag: u8,
    pub depth: u32,
    pub offset: usize,
    pub len: usize,
}

pub const BER_MAX_NODES: usize = 256;
pub const BER_MAX_STACK: usize = 16;
pub const BER_INLINE_NODES: usize = 16;

/// SmallVec-style walk result: 16 nodes live on the stack. Spill to heap only
/// when a PDU actually has more than 16 TLVs (hostile or huge MMS).
#[derive(Debug, Clone)]
pub struct BerWalk {
    inline: [BerNode; BER_INLINE_NODES],
    len: usize,
    spill: Vec<BerNode>,
}

impl BerWalk {
    fn empty() -> Self {
        Self {
            inline: [BerNode {
                tag: 0,
                depth: 0,
                offset: 0,
                len: 0,
            }; BER_INLINE_NODES],
            len: 0,
            spill: Vec::new(),
        }
    }

    fn push(&mut self, n: BerNode) -> Result<(), ParseFail> {
        let used = if self.spill.is_empty() {
            self.len
        } else {
            self.spill.len()
        };
        if used >= BER_MAX_NODES {
            return Err(ParseFail {
                context: "ber".into(),
                kind: "too_many_nodes".into(),
                remaining_len: 0,
            });
        }
        if self.spill.is_empty() && self.len < BER_INLINE_NODES {
            self.inline[self.len] = n;
            self.len += 1;
            return Ok(());
        }
        if self.spill.is_empty() {
            self.spill.extend_from_slice(&self.inline[..self.len]);
        }
        self.spill.push(n);
        Ok(())
    }

    #[must_use]
    pub fn as_slice(&self) -> &[BerNode] {
        if self.spill.is_empty() {
            &self.inline[..self.len]
        } else {
            &self.spill
        }
    }

    #[must_use]
    pub fn spilled(&self) -> bool {
        !self.spill.is_empty()
    }
}

struct BerHdr {
    tag: u8,
    header_len: usize,
    value_len: usize,
}

fn parse_ber_hdr(input: &[u8]) -> Result<BerHdr, ParseFail> {
    if input.len() < 2 {
        return Err(ParseFail {
            context: "ber".into(),
            kind: "truncated".into(),
            remaining_len: input.len(),
        });
    }
    let tag = input[0];
    let (len, hdr) = ber_length(&input[1..])?;
    let header_len = 1 + hdr;
    let end = header_len.checked_add(len).ok_or(ParseFail {
        context: "ber".into(),
        kind: "overflow".into(),
        remaining_len: input.len(),
    })?;
    if end > input.len() {
        return Err(ParseFail {
            context: "ber".into(),
            kind: "length_vs_buffer".into(),
            remaining_len: input.len(),
        });
    }
    Ok(BerHdr {
        tag,
        header_len,
        value_len: len,
    })
}

pub fn parse_ber_tlv(input: &[u8], max_depth: u32, depth: u32) -> Result<BerTlv<'_>, ParseFail> {
    if depth > max_depth {
        return Err(ParseFail {
            context: "ber".into(),
            kind: "max_depth".into(),
            remaining_len: input.len(),
        });
    }
    let hdr = parse_ber_hdr(input)?;
    Ok(BerTlv {
        tag: hdr.tag,
        value: &input[hdr.header_len..hdr.header_len + hdr.value_len],
    })
}

/// Flat iterative BER/MMS walker. Nesting lives on a fixed `[Frame; 17]` (no heap).
/// Nodes use an inline 16-slot array; heap spill only past 16 TLVs.
pub fn walk_ber_iterative(input: &[u8], max_depth: u32) -> Result<BerWalk, ParseFail> {
    #[derive(Clone, Copy)]
    struct Frame {
        off: usize,
        end: usize,
        depth: u32,
    }
    let empty = Frame {
        off: 0,
        end: 0,
        depth: 0,
    };
    let mut stack = [empty; BER_MAX_STACK + 1];
    let mut sp = 0usize;
    stack[0] = Frame {
        off: 0,
        end: input.len(),
        depth: 0,
    };
    sp = 1;
    let mut nodes = BerWalk::empty();
    while sp > 0 {
        sp -= 1;
        let mut frame = stack[sp];
        if frame.depth > max_depth {
            return Err(ParseFail {
                context: "ber".into(),
                kind: "max_depth".into(),
                remaining_len: input.len().saturating_sub(frame.off),
            });
        }
        while frame.off < frame.end {
            let slice = &input[frame.off..frame.end];
            let hdr = parse_ber_hdr(slice)?;
            let value_off = frame.off + hdr.header_len;
            let value_end = value_off + hdr.value_len;
            if value_end > frame.end {
                return Err(ParseFail {
                    context: "ber".into(),
                    kind: "length_vs_buffer".into(),
                    remaining_len: frame.end.saturating_sub(frame.off),
                });
            }
            nodes.push(BerNode {
                tag: hdr.tag,
                depth: frame.depth,
                offset: value_off,
                len: hdr.value_len,
            })?;
            frame.off = value_end;
            let constructed = hdr.tag & 0x20 != 0;
            if constructed && hdr.value_len > 0 {
                let child_depth = frame.depth.saturating_add(1);
                if child_depth > max_depth {
                    return Err(ParseFail {
                        context: "ber".into(),
                        kind: "max_depth".into(),
                        remaining_len: hdr.value_len,
                    });
                }
                if frame.off < frame.end {
                    if sp >= stack.len() {
                        return Err(ParseFail {
                            context: "ber".into(),
                            kind: "max_depth".into(),
                            remaining_len: frame.end.saturating_sub(frame.off),
                        });
                    }
                    stack[sp] = Frame {
                        off: frame.off,
                        end: frame.end,
                        depth: frame.depth,
                    };
                    sp += 1;
                }
                if sp >= stack.len() {
                    return Err(ParseFail {
                        context: "ber".into(),
                        kind: "max_depth".into(),
                        remaining_len: hdr.value_len,
                    });
                }
                stack[sp] = Frame {
                    off: value_off,
                    end: value_end,
                    depth: child_depth,
                };
                sp += 1;
                break;
            }
        }
    }
    Ok(nodes)
}

fn ber_length(input: &[u8]) -> Result<(usize, usize), ParseFail> {
    let first = *input.first().ok_or(ParseFail {
        context: "ber_len".into(),
        kind: "truncated".into(),
        remaining_len: 0,
    })?;
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let nbytes = (first & 0x7f) as usize;
    if nbytes == 0 || nbytes > 4 || input.len() < 1 + nbytes {
        return Err(ParseFail {
            context: "ber_len".into(),
            kind: "indefinite_or_oob".into(),
            remaining_len: input.len(),
        });
    }
    let mut len = 0usize;
    for b in &input[1..1 + nbytes] {
        len = len
            .checked_mul(256)
            .and_then(|v| v.checked_add(*b as usize))
            .ok_or(ParseFail {
                context: "ber_len".into(),
                kind: "overflow".into(),
                remaining_len: input.len(),
            })?;
    }
    Ok((len, 1 + nbytes))
}

pub fn parse_goose_frame(input: &[u8]) -> Result<GooseFrame<'_>, ParseFail> {
    let (eth, rest) = parse_ethernet(input)?;
    if eth.ethertype != GOOSE_ETHERTYPE {
        return Err(ParseFail {
            context: "goose".into(),
            kind: "wrong_ethertype".into(),
            remaining_len: rest.len(),
        });
    }
    if rest.len() < 8 {
        return Err(ParseFail {
            context: "goose".into(),
            kind: "truncated_appid".into(),
            remaining_len: rest.len(),
        });
    }
    let appid = u16::from_be_bytes([rest[0], rest[1]]);
    let length = u16::from_be_bytes([rest[2], rest[3]]);
    if usize::from(length) > rest.len() {
        return Err(ParseFail {
            context: "goose".into(),
            kind: "goose_length_vs_buffer".into(),
            remaining_len: rest.len(),
        });
    }
    let apdu = rest.get(8..).unwrap_or(&[]);
    let mut st_num = None;
    let mut sq_num = None;
    let mut simulation = false;
    let mut ttl = None;
    if let Ok(nodes) = walk_ber_iterative(apdu, 8) {
        for n in nodes.as_slice() {
            let value = apdu.get(n.offset..n.offset + n.len).unwrap_or(&[]);
            match n.tag {
                0x85 => st_num = ber_u32(value),
                0x86 => sq_num = ber_u32(value),
                0x87 => simulation = value.first().copied().unwrap_or(0) != 0,
                0x81 => ttl = ber_u32(value),
                _ => {}
            }
        }
    }
    Ok(GooseFrame {
        eth,
        goose: GooseHeader { appid, length },
        st_num,
        sq_num,
        simulation,
        time_allowed_to_live: ttl,
        apdu,
    })
}

fn ber_u32(v: &[u8]) -> Option<u32> {
    if v.is_empty() || v.len() > 4 {
        return None;
    }
    let mut n = 0u32;
    for b in v {
        n = n.saturating_mul(256).saturating_add(u32::from(*b));
    }
    Some(n)
}

pub fn parse_sv_frame(input: &[u8]) -> Result<EthernetHeader, ParseFail> {
    let (eth, rest) = parse_ethernet(input)?;
    if eth.ethertype != SV_ETHERTYPE {
        return Err(ParseFail {
            context: "sv".into(),
            kind: "wrong_ethertype".into(),
            remaining_len: rest.len(),
        });
    }
    if rest.len() < 8 {
        return Err(ParseFail {
            context: "sv".into(),
            kind: "truncated".into(),
            remaining_len: rest.len(),
        });
    }
    Ok(eth)
}

/// MMS over ISO-on-TCP: TPKT + COTP + BER with attribute-depth cap.
pub fn parse_mms_tpkt(input: &[u8], max_attr_depth: u32) -> Result<S7Frame<'_>, ParseFail> {
    let frame = parse_s7_iso_on_tcp(input)?;
    if !frame.userdata.is_empty() {
        let _ = walk_ber_iterative(frame.userdata, max_attr_depth);
    }
    Ok(frame)
}

#[must_use]
pub fn scl_sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_modbus_frame(tx_id: u16, unit: u8, pdu: &[u8]) -> Vec<u8> {
        let mut f = Vec::with_capacity(7 + pdu.len());
        f.extend_from_slice(&tx_id.to_be_bytes());
        f.extend_from_slice(&[0x00, 0x00]);
        let length = u16::try_from(pdu.len() + 1).unwrap_or(0);
        f.extend_from_slice(&length.to_be_bytes());
        f.push(unit);
        f.extend_from_slice(pdu);
        f
    }

    #[test]
    fn modbus_roundtrip_fc03() {
        let frame = build_modbus_frame(0x0001, 0x01, &[0x03, 0x00, 0x00, 0x00, 0x01]);
        let parsed = parse_modbus_frame(&frame).expect("parse");
        assert_eq!(parsed.header.transaction_id, 1);
        assert_eq!(parsed.header.protocol_id, 0);
        assert_eq!(parsed.header.unit_id, 1);
        assert_eq!(parsed.pdu.function, 0x03);
        assert!(!parsed.pdu.exception);
    }

    #[test]
    fn modbus_rejects_nonzero_protocol_id() {
        let mut f = build_modbus_frame(1, 1, &[0x03, 0x00, 0x00, 0x00, 0x01]);
        f[2] = 0x00;
        f[3] = 0x01;
        assert!(parse_modbus_frame(&f).is_err());
    }

    #[test]
    fn modbus_rejects_length_lie() {
        let mut f = build_modbus_frame(1, 1, &[0x03, 0x00, 0x00, 0x00, 0x01]);
        f[4] = 0x00;
        f[5] = 0x20; // claims 32 bytes of unit+pdu
        assert!(parse_modbus_frame(&f).is_err());
    }

    #[test]
    fn modbus_exception_01_enumeration() {
        let f = vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x83, 0x01];
        let parsed = parse_modbus_frame(&f).expect("exc");
        assert!(parsed.pdu.exception);
        assert_eq!(parsed.pdu.exception_code, Some(0x01));
    }

    #[test]
    fn gateway_unit_ids() {
        assert!(is_gateway_unit(0));
        assert!(is_gateway_unit(255));
        assert!(!is_gateway_unit(1));
    }

    #[test]
    fn sanitize_register_bounds() {
        assert_eq!(sanitize_register_u16(50, 0, 100), Some(50));
        assert_eq!(sanitize_register_u16(500, 0, 100), None);
    }

    #[test]
    fn tpkt_rejects_non_rfc1006() {
        let pkt = [0x02, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00];
        assert!(parse_tpkt(&pkt).is_err());
    }

    #[test]
    fn tpkt_rejects_length_lie() {
        // Claims 32-byte TPKT but only 7 bytes are present.
        let pkt = [0x03u8, 0x00, 0x00, 0x20, 0x02, 0xf0, 0x80];
        assert!(parse_tpkt(&pkt).is_err());
    }

    #[test]
    fn s7_cotp_cr_parses() {
        let pkt: [u8; 22] = [
            0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc1, 0x02, 0x01,
            0x00, 0xc2, 0x02, 0x01, 0x02, 0xc0, 0x01, 0x09,
        ];
        let f = parse_s7_iso_on_tcp(&pkt).expect("s7");
        assert_eq!(f.tpkt.version, 3);
        assert_eq!(f.cotp.pdu_type, 0xe0);
    }

    #[test]
    fn dnp3_crc_known_vector() {
        // CRC-16/DNP (poly 0x3D65 reflected 0xA6BC, init 0, xorout 0xFFFF).
        // Check value for ASCII "123456789" is 0xEA82 (catalogue CRC-16/DNP).
        assert_eq!(dnp3_crc(b"123456789"), 0xEA82);
        // Link-status request header 05 64 05 C4 dest=1 src=4.
        let hdr = [0x05u8, 0x64, 0x05, 0xC4, 0x01, 0x00, 0x00, 0x04];
        let crc = dnp3_crc(&hdr);
        assert_eq!(crc, 0xADF1);
        assert_eq!(crc.to_le_bytes(), [0xF1, 0xAD]);
    }

    #[test]
    fn dnp3_rejects_bad_start() {
        let buf = [0x05u8, 0x65, 0x05, 0xC4, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00];
        assert!(parse_dnp3_link(&buf).is_err());
    }

    #[test]
    fn dnp3_file_transfer_object_blocked() {
        let err = walk_dnp3_objects(&[70, 2, 0x00], 4).unwrap_err();
        assert_eq!(err.kind, "file_transfer_group");
    }

    #[test]
    fn dnp3_object_depth_cap() {
        assert!(walk_dnp3_objects(&[1, 2, 0], 0).is_err());
    }

    #[test]
    fn goose_ethertype_and_appid() {
        let mut frame = vec![0u8; 14 + 8];
        frame[12] = 0x88;
        frame[13] = 0xB8;
        frame[14] = 0x00;
        frame[15] = 0x01; // APPID
        frame[16] = 0x00;
        frame[17] = 0x08; // length of remaining GOOSE header
        let g = parse_goose_frame(&frame).expect("goose");
        assert_eq!(g.goose.appid, 1);
        assert_eq!(g.eth.ethertype, GOOSE_ETHERTYPE);
    }

    #[test]
    fn sv_rejects_goose_ethertype() {
        let mut frame = vec![0u8; 22];
        frame[12] = 0x88;
        frame[13] = 0xB8;
        assert!(parse_sv_frame(&frame).is_err());
    }

    #[test]
    fn ber_rejects_overlong_and_deep() {
        assert!(parse_ber_tlv(&[0x30, 0x04, 1, 2, 3, 4], 0, 1).is_err());
        // length claims 200 bytes, buffer has 2
        assert!(parse_ber_tlv(&[0x30, 0x81, 0xC8], 8, 0).is_err());
    }

    fn nest_ber(levels: usize) -> Vec<u8> {
        let mut v = vec![0x04, 0x01, 0xAA];
        for _ in 0..levels {
            let mut outer = Vec::with_capacity(2 + v.len());
            outer.push(0x30);
            outer.push(u8::try_from(v.len()).expect("tiny nest"));
            outer.extend_from_slice(&v);
            v = outer;
        }
        v
    }

    #[test]
    fn ber_iterative_walk_uses_heap_stack_not_recursion() {
        let buf = nest_ber(8);
        let nodes = walk_ber_iterative(&buf, 8).expect("iterative");
        assert!(nodes.as_slice().iter().any(|n| n.tag == 0x04 && n.len == 1));
        assert!(nodes.as_slice().iter().any(|n| n.depth == 8));
        assert!(
            !nodes.spilled(),
            "8-deep nest fits in the 16-slot inline array"
        );
        let err = walk_ber_iterative(&buf, 3).unwrap_err();
        assert_eq!(err.kind, "max_depth");
    }

    fn build_cotp_dt(payload: &[u8], eot: bool) -> Vec<u8> {
        let mut cotp = vec![0x02, 0xf0, if eot { 0x80 } else { 0x00 }];
        cotp.extend_from_slice(payload);
        let total = u16::try_from(4 + cotp.len()).expect("dt size");
        let mut pkt = vec![0x03, 0x00];
        pkt.extend_from_slice(&total.to_be_bytes());
        pkt.extend(cotp);
        pkt
    }

    #[test]
    fn cotp_assembler_joins_two_dt_fragments() {
        let a = build_cotp_dt(b"AAAA", false);
        let b = build_cotp_dt(b"BBBB", true);
        let mut asm = CotpAssembler::new();
        assert!(asm.push(&a).expect("frag1").is_none());
        let done = asm.push(&b).expect("frag2").expect("eot");
        assert_eq!(done.userdata, b"AAAABBBB");
        assert_eq!(done.fragments, 2);
    }

    #[test]
    fn cotp_assembler_rejects_overflow() {
        let huge = vec![0u8; COTP_ASSEMBLY_CAP + 1];
        let pkt = build_cotp_dt(&huge, true);
        let mut asm = CotpAssembler::new();
        let err = asm.push(&pkt).unwrap_err();
        assert_eq!(err.kind, "assembly_overflow");
    }

    #[test]
    fn cotp_assembler_drops_slowloris_fragments() {
        let a = build_cotp_dt(b"AAAA", false);
        let b = build_cotp_dt(b"BBBB", true);
        let mut asm = CotpAssembler::new();
        assert!(asm.push(&a).expect("frag1").is_none());
        std::thread::sleep(MAX_COTP_FRAGMENT_TIMEOUT + Duration::from_millis(5));
        assert!(
            asm.timed_out(),
            "incomplete TPDU must expire without a follow-up"
        );
        let err = asm.push(&b).unwrap_err();
        assert_eq!(err.kind, "fragment_timeout");
        let done = asm
            .push(&b)
            .expect("reset after timeout")
            .expect("complete dt");
        assert_eq!(done.userdata, b"BBBB");
    }

    #[test]
    fn scl_hash_is_stable() {
        let a = scl_sha256_hex(b"<SCL/>");
        let b = scl_sha256_hex(b"<SCL/>");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn modbus_rtu_crc_non_zero() {
        assert_ne!(modbus_rtu_crc(&[0x01, 0x03, 0x00, 0x00, 0x00, 0x01]), 0);
    }
}
