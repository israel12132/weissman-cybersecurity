//! SMB / NetBIOS Security Engine — live, binary-protocol assessment of Windows file-sharing exposure.
//!
//! This is a **real** protocol probe, not a port-knock with canned CVE text. It speaks SMB on the
//! wire — exactly what the top vulnerability scanners (Tenable Nessus, Rapid7, Qualys) and
//! `nmap`'s `smb-*` scripts do — and reports only what the target actually answered:
//!
//!   * **SMB2/SMB3 NEGOTIATE** — real dialect negotiation; parses the server's max dialect, signing
//!     posture (enabled / **required**), capabilities, server GUID and uptime. Signing-not-required
//!     is the precondition for NTLM relay (PetitPotam-class) attacks.
//!   * **SMBv1 detection** — a dedicated SMBv1-only NEGOTIATE; a valid SMBv1 answer means the host
//!     still speaks the protocol behind **EternalBlue (MS17-010 / CVE-2017-0144)** — the WannaCry /
//!     NotPetya vector.
//!   * **SMBGhost surface** — an SMB 3.1.1 NEGOTIATE with contexts; an `SMB2_COMPRESSION_CAPABILITIES`
//!     response context indicates the **CVE-2020-0796** wormable-RCE surface.
//!   * **NTLMSSP info disclosure** — an anonymous SESSION_SETUP elicits the NTLM type-2 challenge,
//!     from which we recover the NetBIOS / DNS computer & domain, the AD forest, and the OS build
//!     (the classic `smb-os-discovery`). EoL Windows builds are flagged.
//!   * **NetBIOS Name Service** (UDP 137) node status — names, roles and the burned-in MAC address.
//!   * **Anonymous / guest IPC$ session** — full SMB2 SESSION_SETUP → TREE_CONNECT to `IPC$` and
//!     named-pipe CREATE (`\epmapper`, `\spoolss`, `\samr`) exactly as BloodHound / CrackMapExec /
//!     Impacket enumerate; only reported when the server returns `STATUS_SUCCESS`.
//!   * **DCE/RPC Endpoint Mapper bind** — a real MSRPC v5 BIND on `\pipe\epmapper`; a BIND_ACK
//!     proves the host exposes the RPC mapper to the caller's session (lateral-movement surface).
//!   * **SMB 3.x encryption posture** — parses `SMB2_ENCRYPTION_CAPABILITIES` negotiate contexts;
//!     SMB3 without mandatory encryption is a downgrade / relay-class weakness.
//!   * **SPNEGO mechanism fingerprint** — Kerberos vs NTLM-only from the NEGOTIATE security blob.
//!   * **NBNS domain-controller role** — `<1C>` / `<1B>` suffixes in the node-status table.
//!   * **Posture score** — weighted aggregate of every observed weakness for executive dashboards.
//!   * **MS17-010 TRANS2 fingerprint** — sends the same Trans2 probe used by Nessus / Nmap
//!     `smb-vuln-ms17-010`; `STATUS_INSUFF_SERVER_RESOURCES` (0xC0000205) = patched, any other
//!     answer on an SMBv1 host = likely vulnerable (reported with observed NTSTATUS only).
//!   * **Extended RPC pipe cartography** — `\efsrpc` (PetitPotam), `\netlogon` (Zerologon surface),
//!     `\winreg`, `\atsvc`, `\srvsvc`, `\wkssvc` plus existing SAMR/LSARPC/SVCCTL/spoolss/epmapper.
//!   * **NTLMv1 / LM weakness** — parsed from real NTLM type-2 negotiate flags on the wire.
//!   * **Implementation fingerprint** — Windows vs Samba from NTLM target info + negotiate capabilities.
//!   * **PetitPotam toxic combination** — correlates signing-not-required + EFSRPC pipe + DC/domain role.
//!   * **Zerologon surface correlator** — Netlogon pipe + NBNS DC role on the same host.
//!   * **PrintNightmare correlator** — spoolss pipe + SMB signing-not-required.
//!   * **Guest session detection** — SMB2 SESSION_FLAG_IS_GUEST from real SESSION_SETUP response.
//!   * **SMB metrics telemetry** — pipe matrix, compliance tags (CIS/NIST/PCI/ISO), probe counts for the GUI.
//!
//! Every knob (ports, per-check toggles, timeout) is driven from the live scan request body
//! (`POST /api/command-center/scan` → `EngineRunContext::job_params`) via [`ArsenalConfig`]. After
//! the probes, a correlator chains the observed weaknesses into a concrete takeover/ransomware
//! attack path. Nothing is fabricated — a finding requires an observed protocol response.
//!
//! MITRE: T1021.002 (SMB/Windows Admin Shares), T1210 (Exploitation of Remote Services),
//! T1187 (Forced Authentication / NTLM relay), T1018 / T1046 (Remote System & Service Discovery).

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{extract_host, udp_probe_response};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const ENGINE_ID: &str = "smb_netbios";

// ── NetBIOS Session Service (NBSS) framing ──────────────────────────────────────────────────────

/// Wrap an SMB message in the 4-byte NBSS header (type 0x00 = session message, 24-bit length).
fn nbss_wrap(smb: &[u8]) -> Vec<u8> {
    let len = smb.len();
    let mut out = Vec::with_capacity(len + 4);
    out.push(0x00);
    out.push(((len >> 16) & 0xff) as u8);
    out.push(((len >> 8) & 0xff) as u8);
    out.push((len & 0xff) as u8);
    out.extend_from_slice(smb);
    out
}

/// Read one complete NBSS-framed message (header + declared body length) from a stream.
async fn read_nbss(stream: &mut TcpStream, timeout_ms: u64) -> Option<Vec<u8>> {
    let mut hdr = [0u8; 4];
    timeout(Duration::from_millis(timeout_ms), stream.read_exact(&mut hdr))
        .await
        .ok()?
        .ok()?;
    let len = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | (hdr[3] as usize);
    if len == 0 || len > 131_072 {
        return None;
    }
    let mut body = vec![0u8; len];
    timeout(Duration::from_millis(timeout_ms), stream.read_exact(&mut body))
        .await
        .ok()?
        .ok()?;
    let mut full = Vec::with_capacity(4 + len);
    full.extend_from_slice(&hdr);
    full.extend_from_slice(&body);
    Some(full)
}

async fn connect(host: &str, port: u16, timeout_ms: u64) -> Option<TcpStream> {
    let addr = format!("{}:{}", host, port);
    timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr))
        .await
        .ok()?
        .ok()
}

// ── SMB2 message construction ───────────────────────────────────────────────────────────────────

/// 64-byte SMB2 (sync) header.
fn smb2_header(command: u16, message_id: u64, session_id: u64) -> Vec<u8> {
    let mut h = Vec::with_capacity(64);
    h.extend_from_slice(&[0xFE, b'S', b'M', b'B']); // ProtocolId
    h.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    h.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    h.extend_from_slice(&0u32.to_le_bytes()); // Status (request)
    h.extend_from_slice(&command.to_le_bytes()); // Command
    h.extend_from_slice(&31u16.to_le_bytes()); // CreditRequest
    h.extend_from_slice(&0u32.to_le_bytes()); // Flags
    h.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    h.extend_from_slice(&message_id.to_le_bytes()); // MessageId
    h.extend_from_slice(&0u32.to_le_bytes()); // Reserved (former PID)
    h.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    h.extend_from_slice(&session_id.to_le_bytes()); // SessionId
    h.extend_from_slice(&[0u8; 16]); // Signature
    h
}

/// SMB2 NEGOTIATE request. `with_311` adds the SMB 3.1.1 dialect + the mandatory negotiate contexts.
fn build_smb2_negotiate(with_311: bool) -> Vec<u8> {
    let header = smb2_header(0x0000, 0, 0); // NEGOTIATE
    let mut dialects: Vec<u16> = vec![0x0202, 0x0210, 0x0300, 0x0302];
    if with_311 {
        dialects.push(0x0311);
    }
    let mut dpart = Vec::new();
    for d in &dialects {
        dpart.extend_from_slice(&d.to_le_bytes());
    }

    let mut body = Vec::with_capacity(36);
    body.extend_from_slice(&36u16.to_le_bytes()); // StructureSize (fixed)
    body.extend_from_slice(&(dialects.len() as u16).to_le_bytes()); // DialectCount
    body.extend_from_slice(&0x0001u16.to_le_bytes()); // SecurityMode = SIGNING_ENABLED
    body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    body.extend_from_slice(&0u32.to_le_bytes()); // Capabilities

    if with_311 {
        let contexts = build_negotiate_contexts();
        body.extend_from_slice(&[0u8; 16]); // ClientGuid
        let pre_context_len = 64 + 36 + dpart.len();
        let pad = (8 - (pre_context_len % 8)) % 8;
        let context_offset = (pre_context_len + pad) as u32;
        body.extend_from_slice(&context_offset.to_le_bytes()); // NegotiateContextOffset
        body.extend_from_slice(&2u16.to_le_bytes()); // NegotiateContextCount
        body.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
        let mut smb = header;
        smb.extend_from_slice(&body);
        smb.extend_from_slice(&dpart);
        let padded_len = smb.len() + pad;
        smb.resize(padded_len, 0); // 8-byte align before negotiate contexts
        smb.extend_from_slice(&contexts);
        nbss_wrap(&smb)
    } else {
        body.extend_from_slice(&[0u8; 16]); // ClientGuid
        body.extend_from_slice(&0u64.to_le_bytes()); // ClientStartTime
        let mut smb = header;
        smb.extend_from_slice(&body);
        smb.extend_from_slice(&dpart);
        nbss_wrap(&smb)
    }
}

/// SMB 3.1.1 negotiate contexts: preauth-integrity (SHA-512) + encryption (AES-GCM/CCM).
fn build_negotiate_contexts() -> Vec<u8> {
    let mut out = Vec::new();
    let mut preauth = Vec::new();
    preauth.extend_from_slice(&1u16.to_le_bytes()); // HashAlgorithmCount
    preauth.extend_from_slice(&32u16.to_le_bytes()); // SaltLength
    preauth.extend_from_slice(&0x0001u16.to_le_bytes()); // SHA-512
    preauth.extend_from_slice(&[0u8; 32]); // Salt
    push_context(&mut out, 0x0001, &preauth);

    let mut enc = Vec::new();
    enc.extend_from_slice(&2u16.to_le_bytes()); // CipherCount
    enc.extend_from_slice(&0x0002u16.to_le_bytes()); // AES-128-GCM
    enc.extend_from_slice(&0x0001u16.to_le_bytes()); // AES-128-CCM
    push_context(&mut out, 0x0002, &enc);
    out
}

fn push_context(out: &mut Vec<u8>, ctype: u16, data: &[u8]) {
    while out.len() % 8 != 0 {
        out.push(0); // 8-byte align between contexts
    }
    out.extend_from_slice(&ctype.to_le_bytes()); // ContextType
    out.extend_from_slice(&(data.len() as u16).to_le_bytes()); // DataLength
    out.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    out.extend_from_slice(data);
}

/// SMB2 SESSION_SETUP request carrying a raw NTLMSSP token in the security buffer.
fn build_smb2_session_setup(security_blob: &[u8], message_id: u64) -> Vec<u8> {
    build_smb2_session_setup_with_session(security_blob, message_id, 0)
}

fn build_smb2_session_setup_with_session(
    security_blob: &[u8],
    message_id: u64,
    session_id: u64,
) -> Vec<u8> {
    let header = smb2_header(0x0001, message_id, session_id); // SESSION_SETUP
    let mut body = Vec::new();
    body.extend_from_slice(&25u16.to_le_bytes()); // StructureSize (24 fixed + 1 buffer byte)
    body.push(0x00); // Flags
    body.push(0x01); // SecurityMode = SIGNING_ENABLED
    body.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    body.extend_from_slice(&0u32.to_le_bytes()); // Channel
    let sec_off = (64u16) + 24u16; // header + fixed body
    body.extend_from_slice(&sec_off.to_le_bytes()); // SecurityBufferOffset
    body.extend_from_slice(&(security_blob.len() as u16).to_le_bytes()); // SecurityBufferLength
    body.extend_from_slice(&0u64.to_le_bytes()); // PreviousSessionId
    let mut smb = header;
    smb.extend_from_slice(&body);
    smb.extend_from_slice(security_blob);
    nbss_wrap(&smb)
}

/// NTLMSSP NEGOTIATE (type 1) message — requests target info + version from the server.
fn build_ntlm_type1() -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(b"NTLMSSP\x00");
    m.extend_from_slice(&1u32.to_le_bytes()); // MessageType = 1
    let flags: u32 = 0x0000_0001 // UNICODE
        | 0x0000_0002 // OEM
        | 0x0000_0004 // REQUEST_TARGET
        | 0x0000_0200 // NTLM
        | 0x0000_8000 // ALWAYS_SIGN
        | 0x0008_0000 // EXTENDED_SESSIONSECURITY
        | 0x0080_0000 // TARGET_INFO
        | 0x0200_0000 // VERSION
        | 0x2000_0000 // 128-bit
        | 0x8000_0000; // 56-bit
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(&[0u8; 8]); // DomainName fields (empty)
    m.extend_from_slice(&[0u8; 8]); // Workstation fields (empty)
    m.extend_from_slice(&[6u8, 1, 0, 0, 0, 0, 0, 0x0f]); // Version 6.1, NTLM revision 15
    m
}

/// NTLMSSP AUTHENTICATE (type 3) with empty credentials — classic null/guest session probe.
fn build_ntlm_type3_null(challenge_msg: &[u8]) -> Option<Vec<u8>> {
    let base = find_subsequence(challenge_msg, b"NTLMSSP\x00")?;
    let msg = &challenge_msg[base..];
    if msg.len() < 32 || u32::from_le_bytes(msg[8..12].try_into().ok()?) != 2 {
        return None;
    }
    let flags = u32::from_le_bytes(msg[20..24].try_into().ok()?);
    let mut m = Vec::new();
    m.extend_from_slice(b"NTLMSSP\x00");
    m.extend_from_slice(&3u32.to_le_bytes());
    // LM response — empty.
    m.extend_from_slice(&0u16.to_le_bytes());
    m.extend_from_slice(&0u16.to_le_bytes());
    m.extend_from_slice(&0u32.to_le_bytes());
    // NT response — empty.
    m.extend_from_slice(&0u16.to_le_bytes());
    m.extend_from_slice(&0u16.to_le_bytes());
    m.extend_from_slice(&0u32.to_le_bytes());
    // Domain, user, workstation — all empty.
    for _ in 0..3 {
        m.extend_from_slice(&0u16.to_le_bytes());
        m.extend_from_slice(&0u16.to_le_bytes());
        m.extend_from_slice(&0u32.to_le_bytes());
    }
    // Encrypted random session key — empty.
    m.extend_from_slice(&0u16.to_le_bytes());
    m.extend_from_slice(&0u16.to_le_bytes());
    m.extend_from_slice(&0u32.to_le_bytes());
    m.extend_from_slice(&flags.to_le_bytes());
    if flags & 0x0200_0000 != 0 {
        m.extend_from_slice(&[0u8; 8]);
    }
    Some(m)
}

const STATUS_SUCCESS: u32 = 0;
const STATUS_MORE_PROCESSING: u32 = 0xC000_0016;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

#[derive(Clone, Debug)]
struct Smb2RespHdr {
    status: u32,
    command: u16,
    session_id: u64,
    tree_id: u32,
}

fn parse_smb2_hdr(resp: &[u8]) -> Option<Smb2RespHdr> {
    if resp.len() < 4 + 64 {
        return None;
    }
    let smb = &resp[4..];
    if smb[0..4] != [0xFE, b'S', b'M', b'B'] {
        return None;
    }
    Some(Smb2RespHdr {
        status: u32::from_le_bytes(smb[8..12].try_into().ok()?),
        command: u16::from_le_bytes(smb[12..14].try_into().ok()?),
        tree_id: u32::from_le_bytes(smb[36..40].try_into().ok()?),
        session_id: u64::from_le_bytes(smb[40..48].try_into().ok()?),
    })
}

/// SMB2 SESSION_SETUP response SessionFlags — bit 0x0001 = IS_GUEST (MS-SMB2).
fn parse_session_setup_guest(resp: &[u8]) -> bool {
    if resp.len() < 4 + 64 + 4 {
        return false;
    }
    let body = &resp[4 + 64..];
    let flags = u16::from_le_bytes([body[2], body[3]]);
    flags & 0x0001 != 0
}

fn parse_create_file_id(resp: &[u8]) -> Option<[u8; 16]> {
    if resp.len() < 4 + 64 + 80 {
        return None;
    }
    let hdr = parse_smb2_hdr(resp)?;
    if hdr.status != STATUS_SUCCESS || hdr.command != 0x0005 {
        return None;
    }
    let body = &resp[4 + 64..];
    let mut fid = [0u8; 16];
    fid.copy_from_slice(&body[64..80]);
    Some(fid)
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

fn build_smb2_tree_connect(path: &str, message_id: u64, session_id: u64) -> Vec<u8> {
    let path_utf = utf16le(path);
    let header = smb2_header(0x0003, message_id, session_id);
    let path_off = 64u16 + 8u16;
    let mut body = Vec::new();
    body.extend_from_slice(&9u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes()); // Flags
    body.extend_from_slice(&path_off.to_le_bytes());
    body.extend_from_slice(&(path_utf.len() as u16).to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    let mut smb = header;
    smb.extend_from_slice(&body);
    smb.extend_from_slice(&path_utf);
    nbss_wrap(&smb)
}

fn build_smb2_create_pipe(pipe_name: &str, message_id: u64, session_id: u64, tree_id: u32) -> Vec<u8> {
    let name = utf16le(pipe_name);
    let mut h = smb2_header(0x0005, message_id, session_id);
    h[36..40].copy_from_slice(&tree_id.to_le_bytes());
    let name_off = 64u16 + 56u16;
    let mut body = Vec::new();
    body.extend_from_slice(&57u16.to_le_bytes()); // StructureSize
    body.push(0x00); // SecurityFlags
    body.extend_from_slice(&0x0012_019Fu32.to_le_bytes()); // DesiredAccess (pipe R/W)
    body.extend_from_slice(&0u32.to_le_bytes()); // FileAttributes
    body.extend_from_slice(&7u32.to_le_bytes()); // ShareAccess R+W+Del
    body.extend_from_slice(&1u32.to_le_bytes()); // CreateDisposition OPEN
    body.extend_from_slice(&0x0000_0040u32.to_le_bytes()); // CreateOptions NON_DIRECTORY
    body.extend_from_slice(&name_off.to_le_bytes());
    body.extend_from_slice(&(name.len() as u16).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsOffset
    body.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsLength
    body.extend_from_slice(&0u8.to_le_bytes()); // Blob offset high byte padding
    let mut smb = h;
    smb.extend_from_slice(&body);
    smb.extend_from_slice(&name);
    nbss_wrap(&smb)
}

fn build_smb2_write(data: &[u8], message_id: u64, session_id: u64, tree_id: u32, file_id: &[u8; 16]) -> Vec<u8> {
    let mut h = smb2_header(0x0009, message_id, session_id);
    h[36..40].copy_from_slice(&tree_id.to_le_bytes());
    let data_off = 64u16 + 48u16;
    let mut body = Vec::new();
    body.extend_from_slice(&49u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes()); // DataOffset high — use 112
    body.extend_from_slice(&data_off.to_le_bytes());
    body.extend_from_slice(&(data.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    body.extend_from_slice(file_id);
    body.extend_from_slice(&0u32.to_le_bytes()); // Channel
    body.extend_from_slice(&0u32.to_le_bytes()); // RemainingBytes
    body.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoOffset
    body.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoLength
    body.extend_from_slice(&0u32.to_le_bytes()); // Flags
    let mut smb = h;
    smb.extend_from_slice(&body);
    smb.extend_from_slice(data);
    nbss_wrap(&smb)
}

fn build_smb2_read(length: u32, message_id: u64, session_id: u64, tree_id: u32, file_id: &[u8; 16]) -> Vec<u8> {
    let mut h = smb2_header(0x0008, message_id, session_id);
    h[36..40].copy_from_slice(&tree_id.to_le_bytes());
    let mut body = Vec::new();
    body.extend_from_slice(&49u16.to_le_bytes());
    body.push(0x00); // Padding
    body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    body.extend_from_slice(&length.to_le_bytes());
    body.extend_from_slice(&0u64.to_le_bytes()); // Offset
    body.extend_from_slice(file_id);
    body.extend_from_slice(&0u32.to_le_bytes()); // MinimumCount
    body.extend_from_slice(&0u32.to_le_bytes()); // Channel
    body.extend_from_slice(&0u32.to_le_bytes()); // RemainingBytes
    body.extend_from_slice(&0u16.to_le_bytes()); // ReadChannelInfoOffset
    body.extend_from_slice(&0u16.to_le_bytes()); // ReadChannelInfoLength
    let mut smb = h;
    smb.extend_from_slice(&body);
    nbss_wrap(&smb)
}

/// MSRPC v5 BIND to the Endpoint Mapper interface (epmapper).
fn build_dce_rpc_bind_epmapper(call_id: u32) -> Vec<u8> {
    let mut pdu = Vec::new();
    pdu.extend_from_slice(&[5, 0, 11, 0x03]); // ver 5.0, BIND, first+last frag
    pdu.extend_from_slice(&[0x10, 0, 0, 0]); // little-endian NDR
    pdu.extend_from_slice(&0u16.to_le_bytes()); // frag_len placeholder
    pdu.extend_from_slice(&0u16.to_le_bytes()); // auth_len
    pdu.extend_from_slice(&call_id.to_le_bytes());
    pdu.extend_from_slice(&4280u16.to_le_bytes()); // max_xmit
    pdu.extend_from_slice(&4280u16.to_le_bytes()); // max_recv
    pdu.extend_from_slice(&0u32.to_le_bytes()); // assoc_group
    pdu.push(1); // num_context_items
    pdu.push(0); // reserved
    pdu.extend_from_slice(&0u16.to_le_bytes()); // reserved2
    // Context 0
    pdu.extend_from_slice(&0u16.to_le_bytes()); // context_id
    pdu.push(1); // num_trans_items
    pdu.push(0); // reserved
    // Abstract syntax: e1af8308-5d1f-11c9-91a4-08002b14a0fa v3.0
    pdu.extend_from_slice(&[
        0x08, 0x83, 0xAF, 0xE1, 0x1F, 0x5D, 0xC9, 0x11, 0x91, 0xA4, 0x08, 0x00, 0x2B, 0x14,
        0xA0, 0xFA,
    ]);
    pdu.extend_from_slice(&3u16.to_le_bytes()); // version major
    pdu.extend_from_slice(&0u16.to_le_bytes()); // version minor
    // Transfer syntax: 8a885d04-1ceb-11c9-9fe8-08002b104280 v2.0
    pdu.extend_from_slice(&[
        0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10,
        0x42, 0x80,
    ]);
    pdu.extend_from_slice(&2u16.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes());
    let frag_len = pdu.len() as u16;
    pdu[8..10].copy_from_slice(&frag_len.to_le_bytes());
    pdu
}

fn dce_rpc_is_bind_ack(data: &[u8]) -> bool {
    data.len() >= 3 && data[0] == 5 && data[2] == 12 // BIND_ACK
}

#[derive(Clone, Debug, Default)]
struct IpcProbeResult {
    ipc_accessible: bool,
    guest_session: bool,
    epmapper_rpc: bool,
    spoolss_pipe: bool,
    samr_pipe: bool,
    lsarpc_pipe: bool,
    svcctl_pipe: bool,
    efsrpc_pipe: bool,
    netlogon_pipe: bool,
    winreg_pipe: bool,
    atsvc_pipe: bool,
    srvsvc_pipe: bool,
    wkssvc_pipe: bool,
    admin_shares: Vec<(String, u32)>,
}

impl IpcProbeResult {
    fn pipe_matrix(&self) -> Value {
        json!({
            "epmapper_rpc": self.epmapper_rpc,
            "spoolss": self.spoolss_pipe,
            "samr": self.samr_pipe,
            "lsarpc": self.lsarpc_pipe,
            "svcctl": self.svcctl_pipe,
            "efsrpc": self.efsrpc_pipe,
            "netlogon": self.netlogon_pipe,
            "winreg": self.winreg_pipe,
            "atsvc": self.atsvc_pipe,
            "srvsvc": self.srvsvc_pipe,
            "wkssvc": self.wkssvc_pipe,
            "admin_shares": self.admin_shares.iter().map(|(n, s)| json!({"share": n, "ntstatus": format!("0x{:08X}", s)})).collect::<Vec<_>>(),
        })
    }

    fn open_pipe_count(&self) -> usize {
        [
            self.spoolss_pipe,
            self.samr_pipe,
            self.lsarpc_pipe,
            self.svcctl_pipe,
            self.efsrpc_pipe,
            self.netlogon_pipe,
            self.winreg_pipe,
            self.atsvc_pipe,
            self.srvsvc_pipe,
            self.wkssvc_pipe,
        ]
        .iter()
        .filter(|&&x| x)
        .count()
    }
}

async fn probe_pipe_create(
    stream: &mut TcpStream,
    pipe: &str,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    timeout_ms: u64,
) -> bool {
    if stream
        .write_all(&build_smb2_create_pipe(pipe, message_id, session_id, tree_id))
        .await
        .is_err()
    {
        return false;
    }
    if let Some(resp) = read_nbss(stream, timeout_ms).await {
        if let Some(hdr) = parse_smb2_hdr(&resp) {
            return hdr.status == STATUS_SUCCESS;
        }
    }
    false
}

async fn try_epmapper_bind(
    stream: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    timeout_ms: u64,
) -> bool {
    if stream
        .write_all(&build_smb2_create_pipe(r"\epmapper", 4, session_id, tree_id))
        .await
        .is_err()
    {
        return false;
    }
    let Some(resp) = read_nbss(stream, timeout_ms).await else {
        return false;
    };
    let Some(fid) = parse_create_file_id(&resp) else {
        return false;
    };
    let bind = build_dce_rpc_bind_epmapper(1);
    if stream
        .write_all(&build_smb2_write(&bind, 5, session_id, tree_id, &fid))
        .await
        .is_err()
    {
        return false;
    }
    if stream
        .write_all(&build_smb2_read(4096, 6, session_id, tree_id, &fid))
        .await
        .is_err()
    {
        return false;
    }
    let Some(read_resp) = read_nbss(stream, timeout_ms).await else {
        return false;
    };
    if read_resp.len() > 4 + 64 + 48 {
        if let Ok(off_bytes) = read_resp[4 + 64 + 2..4 + 64 + 4].try_into() {
            let data_off = u16::from_le_bytes(off_bytes) as usize;
            if data_off + 3 <= read_resp.len() {
                return dce_rpc_is_bind_ack(&read_resp[data_off..]);
            }
        }
    }
    false
}

/// Full SMB2 null-session → IPC$ → named-pipe + DCE/RPC cartography (Impacket / CME class).
async fn ipc_named_pipe_probe(host: &str, port: u16, timeout_ms: u64) -> Option<IpcProbeResult> {
    let mut stream = connect(host, port, timeout_ms).await?;
    stream
        .write_all(&build_smb2_negotiate(false))
        .await
        .ok()?;
    let _neg_resp = read_nbss(&mut stream, timeout_ms).await?;

    stream
        .write_all(&build_smb2_session_setup(&build_ntlm_type1(), 1))
        .await
        .ok()?;
    let sess1 = read_nbss(&mut stream, timeout_ms).await?;
    let hdr1 = parse_smb2_hdr(&sess1)?;
    if hdr1.status != STATUS_MORE_PROCESSING {
        return None;
    }
    let type3 = build_ntlm_type3_null(&sess1)?;
    stream
        .write_all(&build_smb2_session_setup_with_session(&type3, 2, hdr1.session_id))
        .await
        .ok()?;
    let sess2 = read_nbss(&mut stream, timeout_ms).await?;
    let hdr2 = parse_smb2_hdr(&sess2)?;
    if hdr2.status != STATUS_SUCCESS {
        return None;
    }
    let session_id = hdr2.session_id;
    let guest_session = parse_session_setup_guest(&sess2);

    let ipc_path = format!(r"\\{}\IPC$", host);
    stream
        .write_all(&build_smb2_tree_connect(&ipc_path, 3, session_id))
        .await
        .ok()?;
    let tree_resp = read_nbss(&mut stream, timeout_ms).await?;
    let tree_hdr = parse_smb2_hdr(&tree_resp)?;
    if tree_hdr.status != STATUS_SUCCESS {
        return None;
    }
    let tree_id = tree_hdr.tree_id;

    let mut out = IpcProbeResult {
        ipc_accessible: true,
        guest_session,
        ..IpcProbeResult::default()
    };

    out.epmapper_rpc = try_epmapper_bind(&mut stream, session_id, tree_id, timeout_ms).await;

    let pipes: [(&str, fn(&mut IpcProbeResult, bool)); 9] = [
        (r"\spoolss", |o, v| o.spoolss_pipe = v),
        (r"\samr", |o, v| o.samr_pipe = v),
        (r"\lsarpc", |o, v| o.lsarpc_pipe = v),
        (r"\svcctl", |o, v| o.svcctl_pipe = v),
        (r"\efsrpc", |o, v| o.efsrpc_pipe = v),
        (r"\netlogon", |o, v| o.netlogon_pipe = v),
        (r"\winreg", |o, v| o.winreg_pipe = v),
        (r"\atsvc", |o, v| o.atsvc_pipe = v),
        (r"\srvsvc", |o, v| o.srvsvc_pipe = v),
    ];
    let mut mid = 7u64;
    for (pipe, setter) in pipes {
        let ok = probe_pipe_create(&mut stream, pipe, mid, session_id, tree_id, timeout_ms).await;
        setter(&mut out, ok);
        mid += 1;
    }
    out.wkssvc_pipe =
        probe_pipe_create(&mut stream, r"\wkssvc", mid, session_id, tree_id, timeout_ms).await;
    mid += 1;

    // Admin / hidden share tree-connect oracle (C$ / ADMIN$ / PRINT$) on the same session.
    for share in ["C$", "ADMIN$", "PRINT$"] {
        let path = format!(r"\\{}\{}", host, share);
        stream
            .write_all(&build_smb2_tree_connect(&path, mid, session_id))
            .await
            .ok()?;
        if let Some(resp) = read_nbss(&mut stream, timeout_ms).await {
            if let Some(hdr) = parse_smb2_hdr(&resp) {
                if hdr.status == STATUS_SUCCESS || hdr.status == STATUS_ACCESS_DENIED {
                    out.admin_shares.push((share.to_string(), hdr.status));
                }
            }
        }
        mid += 1;
    }

    Some(out)
}

fn cipher_name(c: u16) -> &'static str {
    match c {
        0x0001 => "AES-128-CCM",
        0x0002 => "AES-128-GCM",
        0x0003 => "AES-256-GCM",
        _ => "unknown",
    }
}

fn nbns_suffix_role(suffix: u8) -> Option<&'static str> {
    match suffix {
        0x1B => Some("Domain Master Browser"),
        0x1C => Some("Domain Controller"),
        0x1D => Some("Local Master Browser"),
        0x00 => Some("Workstation"),
        0x20 => Some("File Server"),
        _ => None,
    }
}

fn classify_nbns_roles(names: &[String]) -> Vec<(String, &'static str)> {
    names
        .iter()
        .filter_map(|n| {
            let (base, suf) = n.rsplit_once('<')?;
            let suf = suf.trim_end_matches('>').parse::<u8>().ok()?;
            nbns_suffix_role(suf).map(|role| (base.to_string(), role))
        })
        .collect()
}

fn posture_score(ledger: &Ledger) -> u32 {
    let mut score = 0u32;
    for (tag, sev) in &ledger.items {
        score += match (*tag, *sev) {
            ("ms17_010" | "efsrpc_pipe" | "petitpotam_surface" | "zerologon_surface" | "smbv1", "critical") => 35,
            (_, "critical") => 35,
            ("no_signing" | "smbghost" | "anonymous_ipc" | "epmapper_rpc" | "spoolss_pipe" | "lsarpc_pipe" | "svcctl_pipe" | "efsrpc_pipe" | "ntlm_weak" | "guest_session" | "printnightmare_surface", "high") => 25,
            ("eol_os" | "nbns_dc" | "no_encryption", "high") => 20,
            (_, "high") => 18,
            (_, "medium") => 10,
            _ => 4,
        };
    }
    score.min(100)
}

fn posture_grade(score: u32) -> &'static str {
    match score {
        0..=15 => "A",
        16..=35 => "B",
        36..=55 => "C",
        56..=75 => "D",
        _ => "F",
    }
}

fn filetime_uptime_days(system_time: u64, boot_time: u64) -> Option<f64> {
    if boot_time == 0 || system_time <= boot_time {
        return None;
    }
    let secs = (system_time - boot_time) / 10_000_000;
    Some(secs as f64 / 86_400.0)
}

fn severity_counts(findings: &[Value]) -> Value {
    let mut counts = json!({ "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0 });
    for f in findings {
        if f.get("category").and_then(|c| c.as_str()) == Some("posture_summary") {
            continue;
        }
        let sev = f.get("severity").and_then(|s| s.as_str()).unwrap_or("info");
        if let Some(n) = counts.get_mut(sev) {
            *n = json!(n.as_u64().unwrap_or(0) + 1);
        }
    }
    counts
}

fn build_exposure_graph(host: &str, ledger: &Ledger) -> Value {
    let mut nodes = vec![
        json!({ "id": "internet", "label": "Attacker", "type": "source" }),
        json!({ "id": "smb", "label": format!("SMB {}", host), "type": "service" }),
    ];
    let mut edges: Vec<Value> = vec![json!({ "from": "internet", "to": "smb", "label": "TCP 445" })];
    let pipe_parent = if ledger.has("anonymous_ipc") {
        nodes.push(json!({ "id": "ipc", "label": "IPC$", "type": "share" }));
        edges.push(json!({ "from": "smb", "to": "ipc", "label": "TREE_CONNECT" }));
        "ipc"
    } else {
        "smb"
    };
    if ledger.has("epmapper_rpc") {
        nodes.push(json!({ "id": "epmapper", "label": "epmapper", "type": "rpc" }));
        edges.push(json!({ "from": pipe_parent, "to": "epmapper", "label": "DCE/RPC BIND" }));
    }
    for (pipe, id, label) in [
        ("spoolss_pipe", "spoolss", "Print Spooler"),
        ("samr_pipe", "samr", "SAMR"),
        ("lsarpc_pipe", "lsarpc", "LSARPC"),
        ("svcctl_pipe", "svcctl", "SVCCTL"),
        ("efsrpc_pipe", "efsrpc", "EFSRPC"),
        ("netlogon_pipe", "netlogon", "Netlogon"),
        ("winreg_pipe", "winreg", "Winreg"),
        ("atsvc_pipe", "atsvc", "ATSVC"),
        ("srvsvc_pipe", "srvsvc", "SRVSVC"),
    ] {
        if ledger.has(pipe) {
            nodes.push(json!({ "id": id, "label": label, "type": "exposure" }));
            edges.push(json!({ "from": pipe_parent, "to": id, "label": "named pipe" }));
        }
    }
    if ledger.has("smbv1") || ledger.has("smbghost") || ledger.has("no_signing") {
        nodes.push(json!({ "id": "domain", "label": "Domain takeover", "type": "impact" }));
        edges.push(json!({ "from": "smb", "to": "domain", "label": "lateral movement" }));
    }
    json!({ "nodes": nodes, "edges": edges })
}

fn mac_oui_vendor(mac: &str) -> Option<&'static str> {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() < 6 {
        return None;
    }
    let p = hex[0..6].to_uppercase();
    const VENDORS: &[(&str, &str)] = &[
        ("00155D", "Microsoft"),
        ("001DD8", "Microsoft Hyper-V"),
        ("3C970E", "Microsoft"),
        ("002248", "Microsoft"),
        ("7C1E52", "Microsoft"),
        ("00125A", "Microsoft"),
        ("001F3A", "Microsoft"),
        ("005056", "VMware"),
        ("000C29", "VMware"),
        ("000569", "VMware"),
        ("001C14", "VMware"),
        ("080027", "VirtualBox / Oracle"),
        ("001B21", "Intel"),
        ("001E67", "Intel"),
        ("001517", "Intel"),
        ("00166F", "Intel"),
        ("001E4F", "Intel"),
        ("001A11", "Google"),
        ("001EC9", "Google"),
        ("3C5A37", "Google"),
        ("B827EB", "Raspberry Pi"),
        ("D83ADD", "Raspberry Pi"),
        ("E45F01", "Raspberry Pi"),
        ("001632", "Cisco"),
        ("001A92", "Cisco"),
        ("001B0D", "Cisco"),
        ("001C58", "Cisco"),
        ("002590", "Cisco"),
        ("001422", "Dell"),
        ("00215D", "Dell"),
        ("002564", "Dell"),
        ("0026B9", "Dell"),
        ("001A4B", "Dell"),
        ("002481", "Dell"),
        ("001871", "HP / HPE"),
        ("001635", "HP / HPE"),
        ("002264", "HP / HPE"),
        ("00306E", "HP / HPE"),
        ("001CC4", "HP / HPE"),
        ("001A2B", "Lenovo"),
        ("001E68", "Lenovo"),
        ("0021CC", "Lenovo"),
        ("001D92", "Lenovo"),
        ("001F16", "Lenovo"),
        ("00163E", "Huawei"),
        ("001E0B", "Huawei / QNAP"),
        ("001F29", "Huawei"),
        ("00163F", "Apple"),
        ("001E73", "Apple"),
        ("0021E9", "Apple"),
        ("001A79", "Supermicro"),
        ("001B78", "Supermicro"),
        ("001C42", "Supermicro"),
        ("001A4A", "Citrix"),
        ("001B11", "Citrix / NetApp"),
    ];
    for (prefix, vendor) in VENDORS {
        if p == *prefix {
            return Some(vendor);
        }
    }
    None
}

fn capability_labels(caps: u32) -> Vec<&'static str> {
    let mut out = Vec::new();
    if caps & 0x0000_0001 != 0 {
        out.push("DFS");
    }
    if caps & 0x0000_0002 != 0 {
        out.push("LEASING");
    }
    if caps & 0x0000_0004 != 0 {
        out.push("LARGE_MTU");
    }
    if caps & 0x0000_0008 != 0 {
        out.push("MULTICHANNEL");
    }
    if caps & 0x0000_0010 != 0 {
        out.push("PERSISTENT_HANDLES");
    }
    if caps & 0x0000_0020 != 0 {
        out.push("DIRECTORY_LEASING");
    }
    out
}

fn ransomware_readiness_score(ledger: &Ledger) -> u32 {
    let mut s = posture_score(ledger);
    if ledger.has("ms17_010") {
        s = s.saturating_add(15);
    }
    if ledger.has("efsrpc_pipe") && ledger.has("no_signing") {
        s = s.saturating_add(12);
    }
    if ledger.has("anonymous_ipc") && ledger.has("srvsvc_pipe") {
        s = s.saturating_add(8);
    }
    s.min(100)
}

fn compliance_gaps(ledger: &Ledger) -> Value {
    let mut cis = Vec::new();
    let mut nist = Vec::new();
    let mut pci = Vec::new();
    let mut iso = Vec::new();
    if ledger.has("smbv1") || ledger.has("ms17_010") {
        cis.push("CIS 4.8 — Disable SMBv1");
        nist.push("SI-2 — Flaw remediation (EOL protocol)");
        pci.push("PCI-DSS 2.2 — System hardening");
        iso.push("A.8.8 — Technical vulnerability management");
    }
    if ledger.has("no_signing") {
        cis.push("CIS 4.7 — Require SMB signing");
        nist.push("SC-8 — Transmission confidentiality (signing)");
        pci.push("PCI-DSS 4.1 — Strong cryptography in transit");
        iso.push("A.13.1.1 — Network controls (SMB signing)");
    }
    if ledger.has("no_encryption") {
        nist.push("SC-8 — SMB3 encryption not enforced");
        iso.push("A.10.1.1 — Cryptographic controls in transit");
    }
    if ledger.has("anonymous_ipc") || ledger.has("epmapper_rpc") || ledger.has("guest_session") {
        cis.push("CIS 4.1 — Restrict anonymous access");
        nist.push("AC-3 — Access enforcement");
        iso.push("A.9.4.1 — Restrictions on information access");
    }
    if ledger.has("ntlm_weak") {
        nist.push("IA-5 — Authenticator management (NTLMv1/LM)");
        iso.push("A.9.4.2 — Secure log-on procedures");
    }
    if ledger.has("eol_os") {
        pci.push("PCI-DSS 6.2 — Security patches");
        nist.push("SI-2 — Unsupported OS");
        iso.push("A.8.1.1 — Asset inventory & patch lifecycle");
    }
    if ledger.has("zerologon_surface") || ledger.has("netlogon_pipe") {
        nist.push("SI-2 — Domain controller secure channel hardening");
        iso.push("A.8.8 — Critical AD patch management (Zerologon class)");
    }
    if ledger.has("printnightmare_surface") || ledger.has("spoolss_pipe") {
        cis.push("CIS 4.3 — Disable Print Spooler on non-print servers");
        iso.push("A.12.6.1 — Restrict vulnerable services");
    }
    json!({ "cis": cis, "nist_800_53": nist, "pci_dss": pci, "iso_27001": iso })
}

fn standards_for_category(cat: &str) -> Vec<&'static str> {
    match cat {
        "cve_surface" => vec!["CIS 4.8", "NIST SI-2", "PCI 2.2"],
        "signing_relay" => vec!["CIS 4.7", "NIST SC-8", "PCI 4.1"],
        "encryption" => vec!["NIST SC-8", "CIS 13.8"],
        "ipc_rpc" => vec!["CIS 4.1", "NIST AC-3", "MITRE T1021.002"],
        "fingerprint" => vec!["NIST RA-5", "CIS 7.1"],
        "netbios" => vec!["CIS 12.1", "NIST SC-7"],
        _ => vec![],
    }
}

fn attach_standards(findings: &mut [Value]) {
    for f in findings.iter_mut() {
        if f.get("standards").is_some() {
            continue;
        }
        let cat = f
            .get("category")
            .and_then(|c| c.as_str())
            .unwrap_or("other");
        let stds: Vec<Value> = standards_for_category(cat)
            .iter()
            .map(|s| json!(s))
            .collect();
        if !stds.is_empty() {
            if let Some(obj) = f.as_object_mut() {
                obj.insert("standards".to_string(), json!(stds));
            }
        }
    }
}

fn synthesize_petitpotam_surface(ledger: &Ledger, target: &str, host: &str) -> Option<Value> {
    let has_coerce = ledger.has("no_signing")
        && (ledger.has("efsrpc_pipe") || ledger.has("lsarpc_pipe"));
    let domain_context = ledger.has("nbns_dc") || ledger.has("ntlm_info");
    if !has_coerce || !domain_context {
        return None;
    }
    let steps = vec![
        "Coerce machine account authentication via EFSRPC (PetitPotam-class) to an NTLM listener",
        "Relay the coerced NTLM session to this host (SMB signing not required)",
        "Authenticate as a privileged machine or user account against domain services",
    ];
    let ev = Evidence::new()
        .with("host", host)
        .with("toxic_tags", json!(["no_signing", "efsrpc_pipe", "domain_context"]))
        .check("petitpotam_surface", true, "signing + EFSRPC + domain role observed together");
    let mut f = finding_rich(
        ENGINE_ID,
        "PetitPotam-class domain coercion surface (signing + EFSRPC + domain role)",
        "critical",
        "T1187",
        "The host combines SMB signing-not-required with a reachable EFSRPC/LSARPC pipe and domain-controller or domain-member context — the exact toxic combination for PetitPotam-style authentication coercion against Active Directory. Patch CVE-2021-36942, require SMB signing on all tier-0 systems, and disable unused EFS.",
        target,
        0.92,
        ev,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("category".to_string(), json!("attack_path"));
        obj.insert("attack_path".to_string(), json!(steps));
    }
    Some(f)
}

fn synthesize_zerologon_surface(ledger: &Ledger, target: &str, host: &str) -> Option<Value> {
    if !ledger.has("netlogon_pipe") || !ledger.has("nbns_dc") {
        return None;
    }
    let steps = vec![
        "Identify domain controller via NBNS <1C> registration on a reachable SMB host",
        "Open Netlogon secure-channel RPC pipe (\\\\pipe\\netlogon) from probe session",
        "Exploit Zerologon-class secure-channel flaws on unpatched DCs (CVE-2020-1472) to reset machine account password",
    ];
    let ev = Evidence::new()
        .with("host", host)
        .with("toxic_tags", json!(["netlogon_pipe", "nbns_dc"]))
        .check("zerologon_surface", true, "DC role + reachable Netlogon pipe observed together");
    let mut f = finding_rich(
        ENGINE_ID,
        "Zerologon-class domain controller exposure (Netlogon pipe + DC NBNS role)",
        "critical",
        "T1210",
        "This host advertises itself as a Domain Controller via NetBIOS and exposes the Netlogon secure-channel RPC pipe to the probe session — the exact surface abused by Zerologon (CVE-2020-1472). Tier-0 DCs must never expose SMB/RPC to untrusted networks; verify August 2020 patches and enforce strict firewall segmentation.",
        target,
        0.93,
        ev,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("category".to_string(), json!("attack_path"));
        obj.insert("attack_path".to_string(), json!(steps));
    }
    Some(f)
}

fn synthesize_printnightmare_surface(ledger: &Ledger, target: &str, host: &str) -> Option<Value> {
    if !ledger.has("spoolss_pipe") || !ledger.has("no_signing") {
        return None;
    }
    let steps = vec![
        "Open Print Spooler RPC pipe (\\\\pipe\\spoolss) from anonymous/guest SMB session",
        "Coerce or relay NTLM authentication (SMB signing not required on this host)",
        "Install malicious driver or achieve SYSTEM via PrintNightmare-class primitives (CVE-2021-34527)",
    ];
    let ev = Evidence::new()
        .with("host", host)
        .with("toxic_tags", json!(["spoolss_pipe", "no_signing"]))
        .check("printnightmare_surface", true, "spoolss pipe + signing-not-required observed together");
    let mut f = finding_rich(
        ENGINE_ID,
        "PrintNightmare-class toxic combination (spoolss + SMB signing not required)",
        "critical",
        "T1210",
        "The Print Spooler named pipe is reachable while SMB signing is not required — the combination used in PrintNightmare and coerced-authentication chains to gain SYSTEM or relay credentials. Disable the Spooler service on servers that do not print, require SMB signing, and apply CVE-2021-34527 patches.",
        target,
        0.9,
        ev,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("category".to_string(), json!("attack_path"));
        obj.insert("attack_path".to_string(), json!(steps));
    }
    Some(f)
}

fn build_smb_metrics_finding(
    target: &str,
    host: &str,
    ledger: &Ledger,
    pipe_matrix: &Value,
    probes_run: u32,
    implementation: &str,
    ms17_status: Option<u32>,
    max_dialect: Option<&str>,
    ransomware_score: u32,
    compliance: &Value,
    scan_elapsed_ms: u64,
) -> Value {
    let posture = posture_score(ledger);
    let grade = posture_grade(posture);
    let ev = Evidence::new()
        .with("host", host)
        .with("probes_run", probes_run)
        .with("implementation", implementation)
        .with("pipe_matrix", pipe_matrix.clone())
        .with("posture_score", posture)
        .with("posture_grade", grade)
        .with("ransomware_readiness", ransomware_score)
        .with("compliance_gaps", compliance.clone())
        .with("max_dialect", max_dialect.unwrap_or("unknown"))
        .with("ms17_010_ntstatus", ms17_status.map(|s| format!("0x{:08X}", s)).unwrap_or_default())
        .with("scan_elapsed_ms", scan_elapsed_ms)
        .with(
            "weakness_tags",
            json!(ledger.items.iter().map(|(t, s)| json!({"tag": t, "severity": s})).collect::<Vec<_>>()),
        )
        .check("smb_metrics", true, "telemetry from live protocol probes only");
    let mut m = finding_rich(
        ENGINE_ID,
        &format!(
            "SMB scan telemetry — {} probes, ransomware readiness {}/100, grade {}",
            probes_run, ransomware_score, grade
        ),
        "info",
        "T1595",
        "Executive telemetry bundle: RPC pipe matrix, compliance gap mapping (CIS/NIST/PCI), implementation fingerprint, and ransomware-readiness score derived only from observed wire responses.",
        target,
        0.35,
        ev,
    );
    if let Some(obj) = m.as_object_mut() {
        obj.insert("category".to_string(), json!("smb_metrics"));
        obj.insert("smb_metrics".to_string(), json!({
            "probes_run": probes_run,
            "implementation": implementation,
            "pipe_matrix": pipe_matrix,
            "posture_score": posture,
            "grade": grade,
            "ransomware_readiness": ransomware_score,
            "compliance_gaps": compliance,
            "max_dialect": max_dialect,
            "ms17_010_ntstatus": ms17_status,
            "scan_elapsed_ms": scan_elapsed_ms,
            "weakness_tags": ledger.items.iter().map(|(t, s)| json!({"tag": t, "severity": s})).collect::<Vec<_>>(),
        }));
    }
    m
}

fn apply_finding_categories(findings: &mut [Value]) {
    for f in findings.iter_mut() {
        if f.get("category").is_some() {
            continue;
        }
        let title = f.get("title").and_then(|t| t.as_str()).unwrap_or("").to_lowercase();
        let cat = if title.contains("posture score") {
            "posture_summary"
        } else if title.contains("attack path") {
            "attack_path"
        } else if title.contains("signing") {
            "signing_relay"
        } else if title.contains("encryption") {
            "encryption"
        } else if title.contains("spnego") || title.contains("ntlm (no kerberos") {
            "auth_mechanism"
        } else if title.contains("efsrpc") || title.contains("petitpotam") {
            "ipc_rpc"
        } else if title.contains("ipc$")
            || title.contains("epmapper")
            || title.contains("spooler")
            || title.contains("samr")
            || title.contains("lsarpc")
            || title.contains("svcctl")
            || title.contains("netlogon")
            || title.contains("winreg")
            || title.contains("atsvc")
            || title.contains("srvsvc")
            || title.contains("wkssvc")
        {
            "ipc_rpc"
        } else if title.contains("fingerprint") || title.contains("end-of-life") {
            "fingerprint"
        } else if title.contains("ms17-010") || title.contains("eternalblue") && title.contains("likely") {
            "cve_surface"
        } else if title.contains("smbghost") || title.contains("smbv1") || title.contains("eternalblue") {
            "cve_surface"
        } else if title.contains("netbios") || title.contains("domain controller advertised") {
            "netbios"
        } else if title.contains("session service") || title.contains(":139") {
            "legacy_netbios"
        } else if title.contains("reachable") || title.contains("uptime") {
            "smb_discovery"
        } else {
            "other"
        };
        if let Some(obj) = f.as_object_mut() {
            obj.insert("category".to_string(), json!(cat));
        }
    }
}

// ── SMB2 NEGOTIATE response parsing ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Smb2Negotiate {
    dialect: u16,
    security_mode: u16,
    capabilities: u32,
    server_guid: [u8; 16],
    system_time: u64,
    boot_time: u64,
    compression: bool,
    encryption_ciphers: Vec<u16>,
    preauth_integrity: bool,
    auth_mechanisms: Vec<&'static str>,
}

fn parse_smb2_negotiate(resp: &[u8]) -> Option<Smb2Negotiate> {
    if resp.len() < 4 + 64 + 64 {
        return None;
    }
    let smb = &resp[4..];
    if smb[0..4] != [0xFE, b'S', b'M', b'B'] {
        return None;
    }
    let status = u32::from_le_bytes(smb[8..12].try_into().ok()?);
    let command = u16::from_le_bytes(smb[12..14].try_into().ok()?);
    if status != 0 || command != 0x0000 {
        return None;
    }
    let body = &smb[64..];
    if body.len() < 64 {
        return None;
    }
    let security_mode = u16::from_le_bytes(body[2..4].try_into().ok()?);
    let dialect = u16::from_le_bytes(body[4..6].try_into().ok()?);
    let context_count = u16::from_le_bytes(body[6..8].try_into().ok()?);
    let mut server_guid = [0u8; 16];
    server_guid.copy_from_slice(&body[8..24]);
    let capabilities = u32::from_le_bytes(body[24..28].try_into().ok()?);
    let system_time = u64::from_le_bytes(body[40..48].try_into().ok()?);
    let boot_time = u64::from_le_bytes(body[48..56].try_into().ok()?);
    let sec_buf_offset = u16::from_le_bytes(body[56..58].try_into().ok()?) as usize;
    let sec_buf_len = u16::from_le_bytes(body[58..60].try_into().ok()?) as usize;
    let context_offset = u32::from_le_bytes(body[60..64].try_into().ok()?) as usize;

    let ctx = parse_negotiate_contexts(smb, context_offset, context_count);
    let auth_mechanisms = if sec_buf_len > 0 && sec_buf_offset + sec_buf_len <= smb.len() {
        detect_spnego_mechanisms(&smb[sec_buf_offset..sec_buf_offset + sec_buf_len])
    } else {
        Vec::new()
    };

    Some(Smb2Negotiate {
        dialect,
        security_mode,
        capabilities,
        server_guid,
        system_time,
        boot_time,
        compression: ctx.compression,
        encryption_ciphers: ctx.encryption_ciphers,
        preauth_integrity: ctx.preauth_integrity,
        auth_mechanisms,
    })
}

#[derive(Clone, Debug, Default)]
struct NegotiateContexts {
    compression: bool,
    preauth_integrity: bool,
    encryption_ciphers: Vec<u16>,
}

fn parse_negotiate_contexts(smb: &[u8], mut offset: usize, count: u16) -> NegotiateContexts {
    let mut out = NegotiateContexts::default();
    for _ in 0..count {
        if offset + 8 > smb.len() {
            break;
        }
        let ctype = u16::from_le_bytes([smb[offset], smb[offset + 1]]);
        let dlen = u16::from_le_bytes([smb[offset + 2], smb[offset + 3]]) as usize;
        if offset + 8 + dlen > smb.len() {
            break;
        }
        let data = &smb[offset + 8..offset + 8 + dlen];
        match ctype {
            0x0001 => out.preauth_integrity = !data.is_empty(),
            0x0002 => {
                if data.len() >= 2 {
                    let n = u16::from_le_bytes([data[0], data[1]]) as usize;
                    for i in 0..n.min(16) {
                        let p = 2 + i * 2;
                        if p + 2 <= data.len() {
                            out.encryption_ciphers
                                .push(u16::from_le_bytes([data[p], data[p + 1]]));
                        }
                    }
                }
            }
            0x0003 => out.compression = true,
            _ => {}
        }
        offset += 8 + dlen;
        offset = (offset + 7) & !7;
    }
    out
}

/// Detect Kerberos / NTLM OIDs inside a GSS-SPNEGO security blob from NEGOTIATE.
fn detect_spnego_mechanisms(blob: &[u8]) -> Vec<&'static str> {
    let mut mechs = Vec::new();
    // NTLMSSP signature (raw NTLM without SPNEGO wrapper).
    if blob.windows(7).any(|w| w == b"NTLMSSP") {
        mechs.push("NTLM");
    }
    // Kerberos 5 OID 1.2.840.113554.1.2.2 → DER 06 09 2A 86 48 86 F7 12 01 02 02
    const KRB5_OID: [u8; 11] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02];
    if blob.windows(KRB5_OID.len()).any(|w| w == KRB5_OID) {
        mechs.push("Kerberos");
    }
    // Microsoft Kerberos OID 1.2.840.48018.1.2.2
    const MSKRB_OID: [u8; 11] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x82, 0xF7, 0x12, 0x01, 0x02, 0x02];
    if blob.windows(MSKRB_OID.len()).any(|w| w == MSKRB_OID) {
        mechs.push("Kerberos-MS");
    }
    // SPNEGO OID 1.3.6.1.5.5.2
    const SPNEGO_OID: [u8; 8] = [0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02];
    if blob.windows(SPNEGO_OID.len()).any(|w| w == SPNEGO_OID) && mechs.is_empty() {
        mechs.push("SPNEGO");
    }
    mechs
}

fn signing_enabled(neg: &Smb2Negotiate) -> bool {
    neg.security_mode & 0x0001 != 0
}
fn signing_required(neg: &Smb2Negotiate) -> bool {
    neg.security_mode & 0x0002 != 0
}

fn dialect_name(d: u16) -> &'static str {
    match d {
        0x0202 => "SMB 2.0.2",
        0x0210 => "SMB 2.1",
        0x0300 => "SMB 3.0",
        0x0302 => "SMB 3.0.2",
        0x0311 => "SMB 3.1.1",
        0x02FF => "SMB 2.wildcard",
        _ => "unknown",
    }
}

const STATUS_INSUFF_SERVER_RESOURCES: u32 = 0xC000_0205;

fn parse_smb1_status(resp: &[u8]) -> Option<u32> {
    if resp.len() < 4 + 9 {
        return None;
    }
    let smb = &resp[4..];
    if smb[0..4] != [0xFF, b'S', b'M', b'B'] {
        return None;
    }
    Some(u32::from_le_bytes(smb[5..9].try_into().ok()?))
}

/// MS17-010 safe fingerprint: Trans2 with TotalDataCount=8192 (Nmap/Nessus class).
/// Patched hosts return `STATUS_INSUFF_SERVER_RESOURCES` (0xC0000205).
fn build_smb1_trans2_ms17_check() -> Vec<u8> {
    let mut smb = Vec::new();
    smb.extend_from_slice(&[0xFF, b'S', b'M', b'B']);
    smb.push(0x32); // SMB_COM_TRANSACTION2
    smb.extend_from_slice(&0u32.to_le_bytes());
    smb.push(0x18);
    smb.extend_from_slice(&[0x53, 0xC8]);
    smb.extend_from_slice(&[0x00, 0x00]);
    smb.extend_from_slice(&[0u8; 8]);
    smb.extend_from_slice(&[0x00, 0x00]);
    smb.extend_from_slice(&[0x00, 0x00]);
    smb.extend_from_slice(&[0x2F, 0x4B]);
    smb.extend_from_slice(&[0x00, 0x00]);
    smb.extend_from_slice(&[0x00, 0x00]);
    smb.push(14); // WordCount
    smb.extend_from_slice(&6u16.to_le_bytes()); // TotalParameterCount
    smb.extend_from_slice(&8192u16.to_le_bytes()); // TotalDataCount — MS17-010 oracle
    smb.extend_from_slice(&65535u16.to_le_bytes()); // MaxParameterCount
    smb.extend_from_slice(&65535u16.to_le_bytes()); // MaxDataCount
    smb.push(0); // MaxSetupCount
    smb.extend_from_slice(&0u16.to_le_bytes());
    smb.extend_from_slice(&0u16.to_le_bytes()); // Flags
    smb.extend_from_slice(&0u32.to_le_bytes()); // Timeout
    smb.extend_from_slice(&0u16.to_le_bytes());
    smb.extend_from_slice(&0u16.to_le_bytes()); // ParameterCount
    smb.extend_from_slice(&82u16.to_le_bytes()); // ParameterOffset
    smb.extend_from_slice(&0u16.to_le_bytes()); // DataCount
    smb.extend_from_slice(&82u16.to_le_bytes()); // DataOffset
    smb.push(1); // SetupCount
    smb.extend_from_slice(&0u16.to_le_bytes());
    smb.extend_from_slice(&0x000Eu16.to_le_bytes()); // TRANS2_QUERY_FS_INFORMATION
    smb.extend_from_slice(&0u16.to_le_bytes()); // ByteCount
    nbss_wrap(&smb)
}

#[derive(Clone, Debug)]
struct Ms17Trans2Result {
    status: u32,
    patched: bool,
}

async fn ms17_010_trans2_probe(host: &str, port: u16, timeout_ms: u64) -> Option<Ms17Trans2Result> {
    let mut stream = connect(host, port, timeout_ms).await?;
    stream.write_all(&build_smb1_negotiate()).await.ok()?;
    let neg = read_nbss(&mut stream, timeout_ms).await?;
    if !smb1_negotiate_accepted(&neg) {
        return None;
    }
    stream
        .write_all(&build_smb1_trans2_ms17_check())
        .await
        .ok()?;
    let resp = read_nbss(&mut stream, timeout_ms).await?;
    let status = parse_smb1_status(&resp)?;
    Some(Ms17Trans2Result {
        patched: status == STATUS_INSUFF_SERVER_RESOURCES,
        status,
    })
}

fn nt_status_name(st: u32) -> &'static str {
    match st {
        0 => "STATUS_SUCCESS",
        0xC000_0205 => "STATUS_INSUFF_SERVER_RESOURCES",
        0xC000_0102 => "STATUS_NOT_SUPPORTED",
        0xC000_0022 => "STATUS_ACCESS_DENIED",
        0xC000_0016 => "STATUS_MORE_PROCESSING_REQUIRED",
        _ => "NTSTATUS",
    }
}

// ── SMBv1 NEGOTIATE (EternalBlue surface) ───────────────────────────────────────────────────────

fn build_smb1_negotiate() -> Vec<u8> {
    let mut smb = Vec::new();
    smb.extend_from_slice(&[0xFF, b'S', b'M', b'B']); // protocol
    smb.push(0x72); // SMB_COM_NEGOTIATE
    smb.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NT status
    smb.push(0x18); // Flags
    smb.extend_from_slice(&[0x53, 0xC8]); // Flags2 (0xC853: unicode + NT status + extended sec)
    smb.extend_from_slice(&[0x00, 0x00]); // PIDHigh
    smb.extend_from_slice(&[0u8; 8]); // SecuritySignature
    smb.extend_from_slice(&[0x00, 0x00]); // Reserved
    smb.extend_from_slice(&[0x00, 0x00]); // TID
    smb.extend_from_slice(&[0x2F, 0x4B]); // PIDLow
    smb.extend_from_slice(&[0x00, 0x00]); // UID
    smb.extend_from_slice(&[0x00, 0x00]); // MID
    smb.push(0x00); // WordCount
    let mut dialects = Vec::new();
    for d in ["NT LM 0.12"] {
        dialects.push(0x02); // dialect buffer format
        dialects.extend_from_slice(d.as_bytes());
        dialects.push(0x00);
    }
    smb.extend_from_slice(&(dialects.len() as u16).to_le_bytes()); // ByteCount
    smb.extend_from_slice(&dialects);
    nbss_wrap(&smb)
}

/// True when the response is a successful SMBv1 NEGOTIATE that selected a dialect (SMBv1 is enabled).
fn smb1_negotiate_accepted(resp: &[u8]) -> bool {
    if resp.len() < 4 + 35 {
        return false;
    }
    let smb = &resp[4..];
    if smb[0..4] != [0xFF, b'S', b'M', b'B'] || smb[4] != 0x72 {
        return false;
    }
    let status = u32::from_le_bytes([smb[5], smb[6], smb[7], smb[8]]);
    if status != 0 {
        return false;
    }
    let word_count = smb[32];
    if word_count == 0 {
        return false;
    }
    let dialect_index = u16::from_le_bytes([smb[33], smb[34]]);
    dialect_index != 0xFFFF
}

// ── NTLMSSP type-2 (CHALLENGE) parsing ──────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
struct NtlmInfo {
    target_name: Option<String>,
    netbios_computer: Option<String>,
    netbios_domain: Option<String>,
    dns_computer: Option<String>,
    dns_domain: Option<String>,
    dns_forest: Option<String>,
    os_version: Option<(u8, u8, u16)>,
    negotiate_flags: u32,
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn utf16le_to_string(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
        .trim_end_matches('\u{0}')
        .to_string()
}

fn parse_ntlm_challenge(resp: &[u8]) -> Option<NtlmInfo> {
    let base = find_subsequence(resp, b"NTLMSSP\x00")?;
    let msg = &resp[base..];
    if msg.len() < 48 {
        return None;
    }
    let msg_type = u32::from_le_bytes(msg[8..12].try_into().ok()?);
    if msg_type != 2 {
        return None;
    }
    let tn_len = u16::from_le_bytes(msg[12..14].try_into().ok()?) as usize;
    let tn_off = u32::from_le_bytes(msg[16..20].try_into().ok()?) as usize;
    let flags = u32::from_le_bytes(msg[20..24].try_into().ok()?);
    let ti_len = u16::from_le_bytes(msg[40..42].try_into().ok()?) as usize;
    let ti_off = u32::from_le_bytes(msg[44..48].try_into().ok()?) as usize;

    let os_version = if flags & 0x0200_0000 != 0 && msg.len() >= 56 {
        Some((msg[48], msg[49], u16::from_le_bytes([msg[50], msg[51]])))
    } else {
        None
    };

    let mut info = NtlmInfo {
        os_version,
        negotiate_flags: flags,
        ..NtlmInfo::default()
    };
    if tn_len > 0 && tn_off + tn_len <= msg.len() {
        info.target_name = Some(utf16le_to_string(&msg[tn_off..tn_off + tn_len]));
    }
    if ti_len > 0 && ti_off + ti_len <= msg.len() {
        let mut p = ti_off;
        let end = ti_off + ti_len;
        while p + 4 <= end {
            let av_id = u16::from_le_bytes([msg[p], msg[p + 1]]);
            let av_len = u16::from_le_bytes([msg[p + 2], msg[p + 3]]) as usize;
            p += 4;
            if av_id == 0 || p + av_len > end {
                break;
            }
            let val = utf16le_to_string(&msg[p..p + av_len]);
            match av_id {
                1 => info.netbios_computer = Some(val),
                2 => info.netbios_domain = Some(val),
                3 => info.dns_computer = Some(val),
                4 => info.dns_domain = Some(val),
                5 => info.dns_forest = Some(val),
                _ => {}
            }
            p += av_len;
        }
    }
    Some(info)
}

/// NTLMv1/LM weakness from observed type-2 negotiate flags (not guessed).
fn ntlm_weak_auth_labels(flags: u32) -> Vec<&'static str> {
    let mut out = Vec::new();
    if flags & 0x0008_0000 == 0 {
        out.push("NTLMv1");
    }
    if flags & 0x0000_0080 != 0 {
        out.push("LM");
    }
    if flags & 0x0200_0000 == 0 {
        out.push("no_extended_session_security");
    }
    out
}

fn detect_smb_implementation(neg: &Smb2Negotiate, ntlm: Option<&NtlmInfo>) -> &'static str {
    if let Some(info) = ntlm {
        let blob = [
            info.target_name.as_deref(),
            info.netbios_computer.as_deref(),
            info.dns_computer.as_deref(),
            info.netbios_domain.as_deref(),
        ];
        for s in blob.into_iter().flatten() {
            let u = s.to_uppercase();
            if u.contains("SAMBA") {
                return "Samba";
            }
        }
    }
    if neg.capabilities & 0x0000_0008 != 0 && neg.dialect >= 0x0311 {
        return "Windows (SMB3.1.1)";
    }
    "Windows / SMB-compatible"
}

/// Friendly OS name + End-of-Life judgement from an NTLM (major, minor, build) tuple.
fn windows_release(v: (u8, u8, u16)) -> (String, bool) {
    let (maj, min, build) = v;
    let (name, eol) = match (maj, min) {
        (10, 0) if build >= 22000 => ("Windows 11 / Server 2022+", false),
        (10, 0) => ("Windows 10 / Server 2016-2019", false),
        (6, 3) => ("Windows 8.1 / Server 2012 R2", false),
        (6, 2) => ("Windows 8 / Server 2012", false),
        (6, 1) => ("Windows 7 / Server 2008 R2 (End-of-Life)", true),
        (6, 0) => ("Windows Vista / Server 2008 (End-of-Life)", true),
        (5, _) => ("Windows XP / Server 2003 (End-of-Life)", true),
        _ => ("Unknown Windows build", false),
    };
    (format!("{} [{}.{}.{}]", name, maj, min, build), eol)
}

// ── NetBIOS Name Service (UDP 137) node status ──────────────────────────────────────────────────

/// Encode the wildcard name "*" as a NetBIOS node-status query (NBSTAT).
fn build_nbns_node_status() -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0x13, 0x37]); // Transaction ID
    pkt.extend_from_slice(&[0x00, 0x00]); // Flags
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR counts
    pkt.push(0x20); // name length (32)
                    // First-level-encoded wildcard name "*" + 15 NULs → "CK" + "AA"*15.
    pkt.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    pkt.push(0x00); // name terminator
    pkt.extend_from_slice(&[0x00, 0x21]); // QTYPE = NBSTAT
    pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
    pkt
}

#[derive(Clone, Debug, Default)]
struct NbnsResult {
    names: Vec<String>,
    mac: Option<String>,
}

fn parse_nbns_node_status(resp: &[u8]) -> Option<NbnsResult> {
    // Header(12) + echoed question(34 name + 4) + answer RR header. The number-of-names byte sits at
    // the start of the RDATA. Locate it past the fixed question echo.
    let rdata_names = 12 + 34 + 2 + 2 + 4 + 2; // hdr + name + type + class + ttl + rdlength
    if resp.len() <= rdata_names {
        return None;
    }
    let num = resp[rdata_names] as usize;
    let mut out = NbnsResult::default();
    let mut p = rdata_names + 1;
    for _ in 0..num.min(64) {
        if p + 18 > resp.len() {
            break;
        }
        let raw = &resp[p..p + 15];
        let name = String::from_utf8_lossy(raw).trim().to_string();
        let suffix = resp[p + 15];
        if !name.is_empty() {
            out.names.push(format!("{}<{:02X}>", name, suffix));
        }
        p += 18; // 15 name + 1 suffix + 2 flags
    }
    if p + 6 <= resp.len() {
        let m = &resp[p..p + 6];
        if m.iter().any(|&b| b != 0) {
            out.mac = Some(
                m.iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(":"),
            );
        }
    }
    if out.names.is_empty() && out.mac.is_none() {
        None
    } else {
        Some(out)
    }
}

// ── Exposure ledger → attack-path synthesis ─────────────────────────────────────────────────────

#[derive(Default)]
struct Ledger {
    items: Vec<(&'static str, &'static str)>, // (tag, severity)
}
impl Ledger {
    fn add(&mut self, tag: &'static str, severity: &'static str) {
        self.items.push((tag, severity));
    }
    fn has(&self, tag: &str) -> bool {
        self.items.iter().any(|(t, _)| *t == tag)
    }
}

// ── Combined SMB2 probe (negotiate + anonymous NTLM session setup) on one connection ────────────

async fn smb2_probe(
    host: &str,
    port: u16,
    timeout_ms: u64,
    want_ntlm: bool,
) -> Option<(Smb2Negotiate, Option<NtlmInfo>)> {
    let mut stream = connect(host, port, timeout_ms).await?;
    if stream
        .write_all(&build_smb2_negotiate(false))
        .await
        .is_err()
    {
        return None;
    }
    let neg_resp = read_nbss(&mut stream, timeout_ms).await?;
    let neg = parse_smb2_negotiate(&neg_resp)?;
    let mut ntlm = None;
    if want_ntlm {
        let ss = build_smb2_session_setup(&build_ntlm_type1(), 1);
        if stream.write_all(&ss).await.is_ok() {
            if let Some(ss_resp) = read_nbss(&mut stream, timeout_ms).await {
                ntlm = parse_ntlm_challenge(&ss_resp);
            }
        }
    }
    Some((neg, ntlm))
}

/// Separate SMB 3.1.1 negotiate to detect the SMBGhost (compression) surface and true max dialect.
async fn smb311_probe(host: &str, port: u16, timeout_ms: u64) -> Option<Smb2Negotiate> {
    let mut stream = connect(host, port, timeout_ms).await?;
    stream.write_all(&build_smb2_negotiate(true)).await.ok()?;
    let resp = read_nbss(&mut stream, timeout_ms).await?;
    parse_smb2_negotiate(&resp)
}

async fn smb1_probe(host: &str, port: u16, timeout_ms: u64) -> bool {
    let Some(mut stream) = connect(host, port, timeout_ms).await else {
        return false;
    };
    if stream.write_all(&build_smb1_negotiate()).await.is_err() {
        return false;
    }
    match read_nbss(&mut stream, timeout_ms).await {
        Some(resp) => smb1_negotiate_accepted(&resp),
        None => false,
    }
}

// ── Engine entry point ──────────────────────────────────────────────────────────────────────────

pub async fn run_smb_netbios_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let scan_start = Instant::now();
    let cfg = ArsenalConfig::from_ctx(ctx);
    let host = extract_host(target);
    if host.is_empty() {
        return EngineResult::error("could not parse host from target");
    }
    let timeout_ms = cfg.timeout_ms(4_000);
    let smb_ports = cfg.ports_or("ports", &[445]);
    let mut findings: Vec<Value> = Vec::new();
    let mut ledger = Ledger::default();
    let mut reachable_port: Option<u16> = None;
    let mut pipe_matrix: Value = json!({});
    let mut ms17_status: Option<u32> = None;
    let mut smb_implementation = "unknown".to_string();
    let mut probes_run: u32 = 0;
    let mut max_dialect_label: Option<String> = None;

    for &port in &smb_ports {
        let want_ntlm = cfg.bool_or("check_ntlm", true);
        let Some((neg, ntlm)) = smb2_probe(&host, port, timeout_ms, want_ntlm).await else {
            continue;
        };
        reachable_port = Some(port);
        probes_run += 1;

        let dialect = neg.dialect;
        let implementation = detect_smb_implementation(&neg, ntlm.as_ref());
        smb_implementation = implementation.to_string();
        if cfg.bool_or("check_implementation", true) {
            let ev = Evidence::new()
                .with("host", host.clone())
                .with("port", port)
                .with("implementation", implementation)
                .with("max_dialect", dialect_name(dialect))
                .check("implementation_fingerprint", true, "derived from NEGOTIATE capabilities + NTLM target info");
            findings.push(finding_rich(
                ENGINE_ID,
                &format!("SMB stack fingerprint: {}", implementation),
                "info",
                "T1046",
                "The server's negotiate response and NTLM target metadata identify the SMB stack implementation — useful for selecting exploit primitives (Windows vs Samba) and patch expectations.",
                target,
                0.35,
                ev,
            ));
        }

        // SMB service reachable (real negotiate completed).
        let ev = Evidence::new()
            .with("host", host.clone())
            .with("port", port)
            .with("max_dialect", dialect_name(dialect))
            .with("dialect_hex", format!("0x{:04x}", dialect))
            .with("server_guid", neg.server_guid.iter().map(|b| format!("{:02x}", b)).collect::<String>())
            .check("smb2_negotiate", true, "server completed an SMB2/3 NEGOTIATE exchange");
        findings.push(finding_rich(
            ENGINE_ID,
            &format!("SMB service reachable on {}:{} ({})", host, port, dialect_name(dialect)),
            "medium",
            "T1021.002",
            "An SMB2/3 service answered a real protocol negotiation. SMB must never be reachable from untrusted networks; if this scan ran from the internet, treat it as high severity and firewall TCP 445 to trusted management ranges only.",
            target,
            0.5,
            ev,
        ));
        ledger.add("smb_reachable", "medium");

        // Server uptime from SMB2 negotiate FILETIME fields (real protocol disclosure).
        if cfg.bool_or("check_uptime", true) {
            if let Some(days) = filetime_uptime_days(neg.system_time, neg.boot_time) {
                let ev = Evidence::new()
                    .with("host", host.clone())
                    .with("port", port)
                    .with("uptime_days", (days * 10.0).round() / 10.0)
                    .check("filetime_uptime", true, "computed from NEGOTIATE SystemTime − SystemStartTime");
                findings.push(finding_rich(
                    ENGINE_ID,
                    &format!("SMB host uptime {:.1} days (from negotiate FILETIME)", days),
                    "info",
                    "T1082",
                    "The SMB2 NEGOTIATE response disclosed system boot time vs current time — useful for patch-reboot correlation and identifying long-lived, potentially unpatched servers.",
                    target,
                    0.3,
                    ev,
                ));
            }
        }

        // Signing posture (NTLM-relay precondition).
        if cfg.bool_or("check_signing", true) {
            if !signing_required(&neg) {
                let enabled = signing_enabled(&neg);
                let (sev, score) = if enabled { ("high", 0.7) } else { ("high", 0.78) };
                let ev = Evidence::new()
                    .with("host", host.clone())
                    .with("port", port)
                    .with("security_mode", format!("0x{:04x}", neg.security_mode))
                    .check("signing_enabled", enabled, "SMB2_NEGOTIATE_SIGNING_ENABLED")
                    .check("signing_required", false, "SMB2_NEGOTIATE_SIGNING_REQUIRED is NOT set");
                findings.push(finding_rich(
                    ENGINE_ID,
                    "SMB signing not required (NTLM relay exposure)",
                    sev,
                    "T1187",
                    "The server does not require SMB signing, so an attacker who can coerce authentication (PetitPotam / Printerbug / LLMNR-NBNS poisoning) can relay NTLM credentials to this host and authenticate as the victim. Enforce SMB signing (Require) via Group Policy on servers and domain controllers.",
                    target,
                    score,
                    ev,
                ));
                ledger.add("no_signing", "high");
            }
        }

        // SMB 3.1.1 negotiate — shared for SMBGhost + encryption posture probes.
        let neg311 = if cfg.bool_or("check_smbghost", true) || cfg.bool_or("check_encryption", true) || cfg.bool_or("check_dialect_downgrade", true) {
            smb311_probe(&host, port, timeout_ms).await
        } else {
            None
        };

        if let Some(ref n311) = neg311 {
            max_dialect_label = Some(dialect_name(n311.dialect).to_string());
            if cfg.bool_or("check_dialect_downgrade", true) && n311.dialect >= 0x0311 && dialect < 0x0300 {
                let ev = Evidence::new()
                    .with("host", host.clone())
                    .with("port", port)
                    .with("negotiated_dialect", dialect_name(dialect))
                    .with("max_dialect", dialect_name(n311.dialect))
                    .check("dialect_downgrade", true, "server accepts lower dialect while advertising SMB 3.1.1");
                findings.push(finding_rich(
                    ENGINE_ID,
                    &format!(
                        "SMB dialect downgrade accepted ({} while server supports {})",
                        dialect_name(dialect),
                        dialect_name(n311.dialect)
                    ),
                    "medium",
                    "T1557",
                    "The server negotiates a legacy SMB dialect on the first exchange while a separate 3.1.1 negotiate proves support for modern SMB — indicating downgrade acceptance that weakens signing/encryption guarantees on the session.",
                    target,
                    0.58,
                    ev,
                ));
                ledger.add("dialect_downgrade", "medium");
            }
        }

        if cfg.bool_or("check_capabilities", true) {
            let caps = capability_labels(neg.capabilities);
            if !caps.is_empty() {
                let ev = Evidence::new()
                    .with("host", host.clone())
                    .with("port", port)
                    .with("capabilities", json!(caps))
                    .with("capabilities_raw", format!("0x{:08x}", neg.capabilities))
                    .check("smb2_capabilities", true, "SMB2_GLOBAL_CAP_* flags from NEGOTIATE response");
                findings.push(finding_rich(
                    ENGINE_ID,
                    &format!("SMB server capabilities: {}", caps.join(", ")),
                    "info",
                    "T1046",
                    "The NEGOTIATE response advertises global capabilities (DFS, leasing, multichannel, etc.) — useful for mapping lateral-movement primitives and expected Windows feature set.",
                    target,
                    0.32,
                    ev,
                ));
            }
        }

        // SMB3 encryption posture — ciphers advertised via 3.1.1 negotiate contexts.
        if cfg.bool_or("check_encryption", true) {
            if let Some(ref n311) = neg311 {
                if !n311.encryption_ciphers.is_empty() {
                    let cipher_labels: Vec<&str> = n311
                        .encryption_ciphers
                        .iter()
                        .map(|c| cipher_name(*c))
                        .collect();
                    let ev = Evidence::new()
                        .with("host", host.clone())
                        .with("port", port)
                        .with("dialect", dialect_name(n311.dialect))
                        .with("encryption_ciphers", json!(cipher_labels))
                        .with("preauth_integrity", n311.preauth_integrity)
                        .check("encryption_available", true, "SMB2_ENCRYPTION_CAPABILITIES in negotiate response");
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "SMB3 encryption available but not enforced on this session",
                        "high",
                        "T1040",
                        "The server advertises SMB3 encryption ciphers yet accepted an unencrypted negotiate/session. Attackers on the same network segment can downgrade or passively capture SMB traffic. Require encryption via Group Policy (RequireEncryption) and block SMB from untrusted VLANs.",
                        target,
                        0.65,
                        ev,
                    ));
                    ledger.add("no_encryption", "high");
                }
            }
        }

        // SPNEGO / Kerberos vs NTLM-only fingerprint from the NEGOTIATE security blob.
        if cfg.bool_or("check_spnego", true) && !neg.auth_mechanisms.is_empty() {
            let mechs: Vec<&str> = neg.auth_mechanisms.clone();
            let ntlm_only = mechs.len() == 1 && mechs[0] == "NTLM";
            let sev = if ntlm_only { "medium" } else { "info" };
            let ev = Evidence::new()
                .with("host", host.clone())
                .with("port", port)
                .with("auth_mechanisms", json!(mechs))
                .check("spnego_mechanisms", true, "auth mechanisms parsed from NEGOTIATE security buffer");
            findings.push(finding_rich(
                ENGINE_ID,
                if ntlm_only {
                    "SMB authentication limited to NTLM (no Kerberos in SPNEGO offer)"
                } else {
                    "SMB SPNEGO authentication mechanisms fingerprinted"
                },
                sev,
                "T1557",
                if ntlm_only {
                    "The server’s SPNEGO offer exposes only NTLM — no Kerberos ticket path — which increases pass-the-hash / relay exposure on flat networks. Join hosts to AD and prefer Kerberos; disable NTLM where feasible (Microsoft NTLM block policies)."
                } else {
                    "The server’s NEGOTIATE security buffer discloses which GSS mechanisms it accepts (Kerberos / NTLM). Useful for mapping domain membership and choosing relay vs ticket attacks."
                },
                target,
                if ntlm_only { 0.55 } else { 0.35 },
                ev,
            ));
            if ntlm_only {
                ledger.add("ntlm_only", "medium");
            }
        }

        // Anonymous IPC$ + named-pipe / DCE/RPC probe (Impacket-class enumeration).
        if cfg.bool_or("check_ipc_pipes", true) {
            if let Some(ipc) = ipc_named_pipe_probe(&host, port, timeout_ms).await {
                if ipc.ipc_accessible {
                    let ev = Evidence::new()
                        .with("host", host.clone())
                        .with("port", port)
                        .check("ipc_tree_connect", true, "anonymous/guest SESSION_SETUP + TREE_CONNECT to IPC$ succeeded");
                    findings.push(finding_rich(
                        ENGINE_ID,
                        &format!("Anonymous SMB IPC$ access on {}:{}", host, port),
                        "high",
                        "T1021.002",
                        "A null or guest SMB session successfully connected to the hidden IPC$ share — the same primitive CrackMapExec / Impacket use to enumerate users, groups and remote services. Restrict anonymous access (RestrictAnonymous, SMB signing) and firewall SMB to management networks.",
                        target,
                        0.82,
                        ev,
                    ));
                    ledger.add("anonymous_ipc", "high");
                }
                if ipc.guest_session {
                    let ev = Evidence::new()
                        .with("host", host.clone())
                        .with("port", port)
                        .with("session_flags", "IS_GUEST")
                        .check("guest_session", true, "SMB2 SESSION_SETUP response set IS_GUEST flag");
                    findings.push(finding_rich(
                        ENGINE_ID,
                        &format!("Guest SMB session accepted on {}:{}", host, port),
                        "high",
                        "T1078",
                        "The server authenticated the probe as a Guest session (SMB2 SESSION_FLAG_IS_GUEST) — weaker than a true null session and often paired with permissive share ACLs. Disable the Guest account, set RestrictAnonymous, and require authenticated SMB access only.",
                        target,
                        0.76,
                        ev,
                    ));
                    ledger.add("guest_session", "high");
                }
                if ipc.epmapper_rpc {
                    let ev = Evidence::new()
                        .with("host", host.clone())
                        .with("port", port)
                        .check("dce_rpc_bind_ack", true, "MSRPC v5 BIND_ACK received on \\\\pipe\\epmapper");
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "DCE/RPC Endpoint Mapper reachable via SMB (epmapper BIND_ACK)",
                        "high",
                        "T1021.002",
                        "The Endpoint Mapper answered a real DCE/RPC BIND on \\\\pipe\\epmapper — proving RPC interface enumeration is possible from this session. Attackers map remotely exposed interfaces (SAMR, LSARPC, SVCCTL) for lateral movement. Block anonymous RPC and require authenticated hardening baselines.",
                        target,
                        0.78,
                        ev,
                    ));
                    ledger.add("epmapper_rpc", "high");
                }
                if ipc.spoolss_pipe {
                    let ev = Evidence::new()
                        .with("host", host.clone())
                        .with("port", port)
                        .check("spoolss_pipe_open", true, "CREATE on \\\\pipe\\spoolss returned STATUS_SUCCESS");
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "Print Spooler RPC pipe exposed (PrintNightmare / spooler abuse surface)",
                        "high",
                        "T1210",
                        "The Print Spooler named pipe (\\\\pipe\\spoolss) opened successfully from the probe session — the precondition for PrintNightmare-class attacks and coerced-authentication chains. Disable the Spooler service on servers that do not print; apply CVE-2021-34527 patches.",
                        target,
                        0.75,
                        ev,
                    ));
                    ledger.add("spoolss_pipe", "high");
                }
                if ipc.samr_pipe {
                    let ev = Evidence::new()
                        .with("host", host.clone())
                        .with("port", port)
                        .check("samr_pipe_open", true, "CREATE on \\\\pipe\\samr returned STATUS_SUCCESS");
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "SAMR RPC pipe exposed (account enumeration surface)",
                        "high",
                        "T1087",
                        "The Security Account Manager Remote Protocol pipe (\\\\pipe\\samr) is reachable — enabling remote user/group enumeration when combined with valid or relayed credentials. Harden SAMR access with RestrictRemoteSAM and least-privilege firewalls.",
                        target,
                        0.7,
                        ev,
                    ));
                    ledger.add("samr_pipe", "high");
                }
                if ipc.lsarpc_pipe {
                    let ev = Evidence::new()
                        .with("host", host.clone())
                        .with("port", port)
                        .check("lsarpc_pipe_open", true, "CREATE on \\\\pipe\\lsarpc returned STATUS_SUCCESS");
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "LSARPC pipe exposed (LSA policy / trust enumeration surface)",
                        "high",
                        "T1087",
                        "The Local Security Authority Remote Protocol pipe (\\\\pipe\\lsarpc) opened successfully — enabling LSA policy reads and trust relationship mapping when combined with valid or relayed credentials.",
                        target,
                        0.68,
                        ev,
                    ));
                    ledger.add("lsarpc_pipe", "high");
                }
                if ipc.svcctl_pipe {
                    let ev = Evidence::new()
                        .with("host", host.clone())
                        .with("port", port)
                        .check("svcctl_pipe_open", true, "CREATE on \\\\pipe\\svcctl returned STATUS_SUCCESS");
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "SVCCTL pipe exposed (remote service control surface)",
                        "high",
                        "T1021.002",
                        "The Service Control Manager pipe (\\\\pipe\\svcctl) is reachable — the persistence primitive used by PsExec-class tools and ransomware for remote service creation. Restrict RPC and enforce tier-0 segmentation.",
                        target,
                        0.72,
                        ev,
                    ));
                    ledger.add("svcctl_pipe", "high");
                }
                if ipc.efsrpc_pipe {
                    let ev = Evidence::new()
                        .with("host", host.clone())
                        .with("port", port)
                        .check("efsrpc_pipe_open", true, "CREATE on \\\\pipe\\efsrpc returned STATUS_SUCCESS");
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "EFSRPC pipe exposed (PetitPotam / MS-EFSR coercion surface)",
                        "critical",
                        "T1187",
                        "The Encrypting File System Remote Protocol pipe (\\\\pipe\\efsrpc) opened from the probe session — the exact primitive abused by PetitPotam to coerce authentication to a domain controller. Patch CVE-2021-36942, disable EFS where unused, and require SMB signing on all tier-0 hosts.",
                        target,
                        0.88,
                        ev,
                    ));
                    ledger.add("efsrpc_pipe", "critical");
                }
                if ipc.netlogon_pipe {
                    let ev = Evidence::new()
                        .with("host", host.clone())
                        .with("port", port)
                        .check("netlogon_pipe_open", true, "CREATE on \\\\pipe\\netlogon returned STATUS_SUCCESS");
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "Netlogon RPC pipe exposed (Zerologon / trust abuse surface)",
                        "high",
                        "T1210",
                        "The Netlogon secure channel pipe (\\\\pipe\\netlogon) is reachable — the surface for Zerologon-class attacks and domain trust manipulation on unpatched domain controllers.",
                        target,
                        0.8,
                        ev,
                    ));
                    ledger.add("netlogon_pipe", "high");
                }
                if ipc.winreg_pipe {
                    let ev = Evidence::new()
                        .with("host", host.clone())
                        .with("port", port)
                        .check("winreg_pipe_open", true, "CREATE on \\\\pipe\\winreg returned STATUS_SUCCESS");
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "Remote Registry pipe exposed (\\\\pipe\\winreg)",
                        "high",
                        "T1021.002",
                        "The Remote Registry service pipe opened successfully — enabling remote registry reads/writes for persistence and credential harvesting when combined with valid or relayed credentials.",
                        target,
                        0.7,
                        ev,
                    ));
                    ledger.add("winreg_pipe", "high");
                }
                if ipc.atsvc_pipe {
                    let ev = Evidence::new()
                        .with("host", host.clone())
                        .with("port", port)
                        .check("atsvc_pipe_open", true, "CREATE on \\\\pipe\\atsvc returned STATUS_SUCCESS");
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "Task Scheduler RPC pipe exposed (\\\\pipe\\atsvc)",
                        "high",
                        "T1053",
                        "The Task Scheduler service pipe (\\\\pipe\\atsvc) is reachable — remote scheduled-task creation for persistence (PsExec/at-style lateral movement).",
                        target,
                        0.72,
                        ev,
                    ));
                    ledger.add("atsvc_pipe", "high");
                }
                if ipc.srvsvc_pipe {
                    let ev = Evidence::new()
                        .with("host", host.clone())
                        .with("port", port)
                        .check("srvsvc_pipe_open", true, "CREATE on \\\\pipe\\srvsvc returned STATUS_SUCCESS");
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "Server Service RPC pipe exposed (\\\\pipe\\srvsvc — share enum surface)",
                        "high",
                        "T1135",
                        "The Server Service pipe (\\\\pipe\\srvsvc) opened — the entry point for NetShareEnumAll share discovery used by every AD penetration tool. Restrict anonymous access and firewall SMB.",
                        target,
                        0.74,
                        ev,
                    ));
                    ledger.add("srvsvc_pipe", "high");
                }
                if ipc.wkssvc_pipe {
                    let ev = Evidence::new()
                        .with("host", host.clone())
                        .with("port", port)
                        .check("wkssvc_pipe_open", true, "CREATE on \\\\pipe\\wkssvc returned STATUS_SUCCESS");
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "Workstation Service RPC pipe exposed (\\\\pipe\\wkssvc)",
                        "medium",
                        "T1018",
                        "The Workstation service pipe is reachable — exposes workstation membership and domain join metadata to the caller's session.",
                        target,
                        0.55,
                        ev,
                    ));
                    ledger.add("wkssvc_pipe", "medium");
                }
                if cfg.bool_or("check_admin_shares", true) {
                    for (share, status) in &ipc.admin_shares {
                        let st_name = nt_status_name(*status);
                        if *status == STATUS_SUCCESS {
                            let ev = Evidence::new()
                                .with("host", host.clone())
                                .with("port", port)
                                .with("share", share.clone())
                                .with("ntstatus", format!("0x{:08X}", status))
                                .check("admin_share_tree_connect", true, "TREE_CONNECT to hidden admin share succeeded");
                            findings.push(finding_rich(
                                ENGINE_ID,
                                &format!("Hidden admin share {} accessible without credentials on {}:{}", share, host, port),
                                "critical",
                                "T1021.002",
                                "A null/guest session successfully connected to a hidden administrative share — catastrophic misconfiguration enabling full filesystem access. Disable guest/null sessions immediately and enforce SMB signing + tier-0 firewalling.",
                                target,
                                0.95,
                                ev,
                            ));
                            ledger.add("admin_share_open", "critical");
                        } else if *status == STATUS_ACCESS_DENIED {
                            let ev = Evidence::new()
                                .with("host", host.clone())
                                .with("port", port)
                                .with("share", share.clone())
                                .with("ntstatus", format!("0x{:08X}", status))
                                .with("ntstatus_name", st_name)
                                .check("admin_share_exists", true, "TREE_CONNECT returned ACCESS_DENIED — share exists");
                            findings.push(finding_rich(
                                ENGINE_ID,
                                &format!("Hidden share {} exists on {} ({} — share present, access denied)", share, host, st_name),
                                "medium",
                                "T1135",
                                "The server responded to a TREE_CONNECT for a hidden administrative share with ACCESS_DENIED rather than BAD_NETWORK_NAME — confirming the share exists and is reachable for authenticated attacks / credential relay.",
                                target,
                                0.52,
                                ev,
                            ));
                            ledger.add("admin_share_exists", "medium");
                        }
                    }
                }
                pipe_matrix = ipc.pipe_matrix();
                probes_run += ipc.open_pipe_count() as u32 + 2;
            }
        }

        // NTLMSSP host / domain / OS fingerprint (anonymous challenge).
        if let Some(info) = ntlm {
            let mut ev = Evidence::new().with("host", host.clone()).with("port", port);
            if let Some(v) = &info.target_name {
                ev = ev.with("target_name", v.clone());
            }
            if let Some(v) = &info.netbios_computer {
                ev = ev.with("netbios_computer", v.clone());
            }
            if let Some(v) = &info.netbios_domain {
                ev = ev.with("netbios_domain", v.clone());
            }
            if let Some(v) = &info.dns_computer {
                ev = ev.with("dns_computer", v.clone());
            }
            if let Some(v) = &info.dns_domain {
                ev = ev.with("dns_domain", v.clone());
            }
            if let Some(v) = &info.dns_forest {
                ev = ev.with("dns_forest", v.clone());
            }
            let mut eol_release: Option<String> = None;
            if let Some(v) = info.os_version {
                let (release, eol) = windows_release(v);
                ev = ev.with("os_release", release.clone());
                if eol {
                    eol_release = Some(release);
                }
            }
            findings.push(finding_rich(
                ENGINE_ID,
                &format!(
                    "SMB host fingerprint: {}",
                    info.dns_computer
                        .clone()
                        .or_else(|| info.netbios_computer.clone())
                        .unwrap_or_else(|| host.clone())
                ),
                "info",
                "T1018",
                "An anonymous NTLM negotiation disclosed the host's NetBIOS/DNS names, Active Directory domain/forest and OS build. This is high-value pre-attack reconnaissance (host & domain targeting); restrict anonymous SMB and NTLM where possible.",
                target,
                0.4,
                ev,
            ));
            ledger.add("ntlm_info", "info");

            if cfg.bool_or("check_ntlm_weak", true) {
                let weak = ntlm_weak_auth_labels(info.negotiate_flags);
                if !weak.is_empty() {
                    let ev = Evidence::new()
                        .with("host", host.clone())
                        .with("port", port)
                        .with("negotiate_flags", format!("0x{:08x}", info.negotiate_flags))
                        .with("weak_auth", json!(weak))
                        .check("ntlm_type2_flags", true, "weak auth modes parsed from NTLM type-2 message");
                    findings.push(finding_rich(
                        ENGINE_ID,
                        &format!("Weak NTLM authentication modes offered: {}", weak.join(", ")),
                        "high",
                        "T1557",
                        "The server's NTLM type-2 challenge advertises legacy authentication modes (NTLMv1 and/or LM) — enabling pass-the-hash and relay attacks against domains that have not enforced NTLMv2-only (Group Policy: Network security: LAN Manager authentication level).",
                        target,
                        0.76,
                        ev,
                    ));
                    ledger.add("ntlm_weak", "high");
                }
            }

            if let Some(release) = eol_release {
                let ev = Evidence::new()
                    .with("host", host.clone())
                    .with("os_release", release.clone())
                    .check("end_of_life_os", true, "OS build no longer receives security updates");
                findings.push(finding_rich(
                    ENGINE_ID,
                    &format!("End-of-Life Windows detected: {}", release),
                    "high",
                    "T1210",
                    "The SMB host reports an End-of-Life Windows build that no longer receives security patches. Unsupported Windows is exposed to a backlog of unpatched RCE vulnerabilities; isolate and upgrade.",
                    target,
                    0.72,
                    ev,
                ));
                ledger.add("eol_os", "high");
            }
        }

        // SMBGhost (CVE-2020-0796) surface via SMB 3.1.1 compression context.
        if cfg.bool_or("check_smbghost", true) {
            if let Some(ref neg311) = neg311 {
                if neg311.dialect == 0x0311 && neg311.compression {
                    let ev = Evidence::new()
                        .with("host", host.clone())
                        .with("port", port)
                        .with("dialect", dialect_name(neg311.dialect))
                        .check("compression_capabilities", true, "SMB2_COMPRESSION_CAPABILITIES present in negotiate response");
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "SMBGhost (CVE-2020-0796) compression surface present",
                        "high",
                        "T1210",
                        "The host negotiates SMB 3.1.1 and advertises SMB compression — the surface for SMBGhost (CVE-2020-0796), a wormable pre-auth RCE in unpatched Windows 10 / Server 1903-1909. Verify the March-2020 patch is applied or disable SMB compression (DisableCompression=1).",
                        target,
                        0.6,
                        ev,
                    ));
                    ledger.add("smbghost", "high");
                }
            }
        }

        // SMBv1 / EternalBlue surface + MS17-010 TRANS2 fingerprint.
        if cfg.bool_or("check_smb1", true) && smb1_probe(&host, port, timeout_ms).await {
            let ev = Evidence::new()
                .with("host", host.clone())
                .with("port", port)
                .check("smbv1_negotiate", true, "server selected an SMBv1 dialect (NT LM 0.12)");
            findings.push(finding_rich(
                ENGINE_ID,
                &format!("SMBv1 enabled on {}:{} (EternalBlue / MS17-010 surface)", host, port),
                "critical",
                "T1210",
                "The host still speaks the obsolete SMBv1 protocol — the EternalBlue (MS17-010 / CVE-2017-0144) surface used by WannaCry and NotPetya, and a prime ransomware lateral-movement vector. Disable SMBv1 entirely (Remove-WindowsFeature FS-SMB1 / registry SMB1=0) on every host.",
                target,
                0.9,
                ev,
            ));
            ledger.add("smbv1", "critical");
            probes_run += 1;

            if cfg.bool_or("check_ms17_010", true) {
                if let Some(ms17) = ms17_010_trans2_probe(&host, port, timeout_ms).await {
                    ms17_status = Some(ms17.status);
                    probes_run += 1;
                    let st_name = nt_status_name(ms17.status);
                    if ms17.patched {
                        let ev = Evidence::new()
                            .with("host", host.clone())
                            .with("port", port)
                            .with("ntstatus", format!("0x{:08X}", ms17.status))
                            .with("ntstatus_name", st_name)
                            .check("ms17_010_trans2", true, "Trans2 probe returned STATUS_INSUFF_SERVER_RESOURCES (patched behavior)");
                        findings.push(finding_rich(
                            ENGINE_ID,
                            &format!("MS17-010 Trans2 probe: patched response ({})", st_name),
                            "info",
                            "T1210",
                            "The MS17-010 Trans2 fingerprint probe returned STATUS_INSUFF_SERVER_RESOURCES — the post-patch behavior documented by Nessus/Nmap. SMBv1 is still enabled (bad hygiene) but this specific Trans2 oracle indicates the EternalBlue kernel path is likely patched.",
                            target,
                            0.45,
                            ev,
                        ));
                    } else {
                        let ev = Evidence::new()
                            .with("host", host.clone())
                            .with("port", port)
                            .with("ntstatus", format!("0x{:08X}", ms17.status))
                            .with("ntstatus_name", st_name)
                            .check("ms17_010_trans2", true, "Trans2 probe did NOT return patched NTSTATUS 0xC0000205");
                        findings.push(finding_rich(
                            ENGINE_ID,
                            &format!(
                                "MS17-010 (EternalBlue) likely vulnerable — Trans2 probe returned {}",
                                st_name
                            ),
                            "critical",
                            "T1210",
                            "On an SMBv1-enabled host, the MS17-010 Trans2 fingerprint did not return the patched STATUS_INSUFF_SERVER_RESOURCES response — the same oracle used by enterprise scanners before exploitation. Treat as critical: apply MS17-010 immediately or disable SMBv1.",
                            target,
                            0.95,
                            ev,
                        ));
                        ledger.add("ms17_010", "critical");
                    }
                }
            }
        }

        // One reachable SMB endpoint is enough unless the operator wants every port enumerated.
        if !cfg.bool_or("scan_all_ports", false) {
            break;
        }
    }

    // NetBIOS Name Service (UDP 137) node status — names + MAC.
    if cfg.bool_or("check_netbios", true) {
        let nb_port = cfg.u64_or("netbios_udp_port", 137) as u16;
        if let Some(resp) = udp_probe_response(&host, nb_port, &build_nbns_node_status()).await {
            if let Some(nb) = parse_nbns_node_status(&resp) {
                let ev = Evidence::new()
                    .with("host", host.clone())
                    .with("udp_port", nb_port)
                    .with("names", json!(nb.names))
                    .with("mac_address", nb.mac.clone().unwrap_or_default())
                    .check("nbns_node_status", true, "NetBIOS node status answered with the name table");
                findings.push(finding_rich(
                    ENGINE_ID,
                    "NetBIOS Name Service information disclosure (UDP 137)",
                    "medium",
                    "T1018",
                    "The NetBIOS Name Service answered an anonymous node-status query, disclosing the computer/workgroup name table and the burned-in MAC address. NBNS is also abusable for LLMNR/NBNS spoofing to capture credentials. Disable NetBIOS over TCP/IP where not required.",
                    target,
                    0.45,
                    ev,
                ));
                ledger.add("netbios_info", "medium");

                if cfg.bool_or("check_mac_vendor", true) {
                    if let Some(ref mac) = nb.mac {
                        if let Some(vendor) = mac_oui_vendor(mac) {
                            let ev = Evidence::new()
                                .with("host", host.clone())
                                .with("mac_address", mac.clone())
                                .with("oui_vendor", vendor)
                                .check("mac_oui_lookup", true, "IEEE OUI prefix matched from NBNS disclosure");
                            findings.push(finding_rich(
                                ENGINE_ID,
                                &format!("NBNS disclosed MAC {} ({})", mac, vendor),
                                "info",
                                "T1018",
                                "The NetBIOS node-status response included a burned-in MAC address whose OUI identifies the hardware vendor — useful for VM/hypervisor detection and physical asset inventory.",
                                target,
                                0.28,
                                ev,
                            ));
                        }
                    }
                }

                // Domain-controller / master-browser roles from NBNS suffix bytes.
                if cfg.bool_or("check_nbns_roles", true) {
                    for (name, role) in classify_nbns_roles(&nb.names) {
                        match role {
                            "Domain Controller" => {
                                let ev = Evidence::new()
                                    .with("host", host.clone())
                                    .with("nbns_name", name.clone())
                                    .with("role", role)
                                    .check("nbns_dc_suffix", true, "NetBIOS name table contains <1C> Domain Controller suffix");
                                findings.push(finding_rich(
                                    ENGINE_ID,
                                    &format!("Domain Controller advertised via NetBIOS: {}", name),
                                    "high",
                                    "T1018",
                                    "The NBNS node-status table includes a <1C> Domain Controller registration — confirming this host is (or impersonates) a DC on the broadcast domain. DCs must never expose NBNS/SMB to untrusted networks; isolate with tier-0 firewalling.",
                                    target,
                                    0.8,
                                    ev,
                                ));
                                ledger.add("nbns_dc", "high");
                            }
                            "Domain Master Browser" => {
                                let ev = Evidence::new()
                                    .with("host", host.clone())
                                    .with("nbns_name", name.clone())
                                    .with("role", role)
                                    .check("nbns_master_browser", true, "NetBIOS name table contains <1B> Domain Master Browser suffix");
                                findings.push(finding_rich(
                                    ENGINE_ID,
                                    &format!("Domain Master Browser role advertised via NetBIOS: {}", name),
                                    "medium",
                                    "T1018",
                                    "The NBNS table includes a <1B> Domain Master Browser registration — confirming domain-wide browser election participation and broadcast-domain membership. Restrict NBNS to management VLANs.",
                                    target,
                                    0.52,
                                    ev,
                                ));
                                ledger.add("nbns_master_browser", "medium");
                            }
                            "File Server" => {
                                let ev = Evidence::new()
                                    .with("host", host.clone())
                                    .with("nbns_name", name.clone())
                                    .with("role", role)
                                    .check("nbns_file_server", true, "NetBIOS name table contains <20> File Server suffix");
                                findings.push(finding_rich(
                                    ENGINE_ID,
                                    &format!("File Server role advertised via NetBIOS: {}", name),
                                    "info",
                                    "T1135",
                                    "The NBNS node-status table includes a <20> File Server registration — useful for mapping file-sharing hosts on the broadcast domain during lateral movement reconnaissance.",
                                    target,
                                    0.3,
                                    ev,
                                ));
                            }
                            "Local Master Browser" => {
                                let ev = Evidence::new()
                                    .with("host", host.clone())
                                    .with("nbns_name", name.clone())
                                    .with("role", role)
                                    .check("nbns_local_browser", true, "NetBIOS name table contains <1D> Local Master Browser suffix");
                                findings.push(finding_rich(
                                    ENGINE_ID,
                                    &format!("Local Master Browser role advertised via NetBIOS: {}", name),
                                    "info",
                                    "T1018",
                                    "The NBNS table includes a <1D> Local Master Browser registration — indicates subnet browser election activity and broadcast-domain exposure.",
                                    target,
                                    0.28,
                                    ev,
                                ));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    // Legacy NetBIOS session service (TCP 139) reachability.
    if cfg.bool_or("check_139", true) {
        if let Some(s) = connect(&host, 139, timeout_ms.min(2000)).await {
            drop(s);
            let ev = Evidence::new()
                .with("host", host.clone())
                .with("port", 139u16)
                .check("tcp_connect", true, "NetBIOS session service accepted a connection");
            findings.push(finding_rich(
                ENGINE_ID,
                &format!("Legacy NetBIOS session service open on {}:139", host),
                "medium",
                "T1021.002",
                "The legacy NetBIOS Session Service (TCP 139) is reachable. It predates direct-hosted SMB (445), weakens the attack surface and supports NTLM relay. Disable NetBIOS over TCP/IP and rely on 445 only, firewalled to trusted ranges.",
                target,
                0.4,
                ev,
            ));
            ledger.add("port139", "medium");
        }
    }

    // PetitPotam-class toxic combination (signing + EFSRPC + domain context).
    if cfg.bool_or("check_petitpotam", true) {
        if let Some(pp) = synthesize_petitpotam_surface(&ledger, target, &host) {
            findings.push(pp);
            ledger.add("petitpotam_surface", "critical");
        }
    }

    if cfg.bool_or("check_zerologon", true) {
        if let Some(zl) = synthesize_zerologon_surface(&ledger, target, &host) {
            findings.push(zl);
            ledger.add("zerologon_surface", "critical");
        }
    }

    if cfg.bool_or("check_printnightmare", true) {
        if let Some(pn) = synthesize_printnightmare_surface(&ledger, target, &host) {
            findings.push(pn);
            ledger.add("printnightmare_surface", "critical");
        }
    }

    // Attack-path synthesis: ransomware / relay takeover from the toxic combination observed.
    if cfg.bool_or("synthesize_attack_path", true) {
        if let Some(ap) = synthesize_attack_path(&ledger, target, &host) {
            findings.push(ap);
        }
    }

    // SMB metrics telemetry for Command Center dashboards.
    if cfg.bool_or("emit_metrics", true) && probes_run > 0 {
        let compliance = compliance_gaps(&ledger);
        let rw = ransomware_readiness_score(&ledger);
        let elapsed = scan_start.elapsed().as_millis() as u64;
        findings.push(build_smb_metrics_finding(
            target,
            &host,
            &ledger,
            &pipe_matrix,
            probes_run,
            &smb_implementation,
            ms17_status,
            max_dialect_label.as_deref(),
            rw,
            &compliance,
            elapsed,
        ));
    }

    // Executive posture score — weighted aggregate of every observed weakness.
    if cfg.bool_or("posture_scoring", true) && !ledger.items.is_empty() {
        let score = posture_score(&ledger);
        let grade = posture_grade(score);
        let counts = severity_counts(&findings);
        let graph = build_exposure_graph(&host, &ledger);
        let ev = Evidence::new()
            .with("host", host.clone())
            .with("posture_score", score)
            .with("posture_grade", grade)
            .with("grade", grade)
            .with("counts", counts.clone())
            .with("exposure_graph", graph.clone())
            .with("observed_weaknesses", json!(ledger.items.iter().map(|(t, s)| json!({"tag": t, "severity": s})).collect::<Vec<_>>()))
            .check("posture_aggregate", true, "score computed from protocol-observed SMB weaknesses only");
        let mut summary = finding_rich(
            ENGINE_ID,
            &format!("SMB/NetBIOS posture score: {}/100 (grade {})", score, grade),
            if score >= 56 { "high" } else if score >= 36 { "medium" } else { "info" },
            "T1595",
            "Weighted aggregate of every weakness this scan observed on the wire — signing, encryption, SMBv1, IPC/RPC exposure, EoL OS and NetBIOS disclosure. Grade F (56+) indicates immediate containment; remediate critical items before the next assessment window.",
            target,
            (score as f64 / 100.0).min(0.95),
            ev,
        );
        if let Some(obj) = summary.as_object_mut() {
            obj.insert("category".to_string(), json!("posture_summary"));
            obj.insert("posture_score".to_string(), json!(score));
            obj.insert("grade".to_string(), json!(grade));
            obj.insert("summary".to_string(), json!(true));
            obj.insert("exposure_graph".to_string(), graph);
            obj.insert("counts".to_string(), counts);
        }
        findings.push(summary);
    }

    apply_finding_categories(&mut findings);
    attach_standards(&mut findings);

    let crit = ledger.items.iter().filter(|(_, s)| *s == "critical").count();
    let msg = if findings.is_empty() {
        format!(
            "smb_netbios: no SMB/NetBIOS service answered on {} (ports {:?})",
            host, smb_ports
        )
    } else {
        format!(
            "smb_netbios: {} finding(s) ({} critical) on {}{}",
            findings.len(),
            crit,
            host,
            reachable_port
                .map(|p| format!(" (SMB on :{})", p))
                .unwrap_or_default()
        )
    };
    EngineResult::ok(findings, msg)
}

fn synthesize_attack_path(ledger: &Ledger, target: &str, host: &str) -> Option<Value> {
    let mut steps: Vec<&str> = Vec::new();
    if ledger.has("smbv1") {
        steps.push("Exploit SMBv1 (EternalBlue/MS17-010) for unauthenticated remote code execution");
    }
    if ledger.has("no_signing") {
        steps.push("Coerce + relay NTLM authentication (signing not required) to authenticate as a privileged account");
    }
    if ledger.has("smbghost") {
        steps.push("Exploit SMB 3.1.1 compression (SMBGhost / CVE-2020-0796) for wormable RCE");
    }
    if ledger.has("anonymous_ipc") || ledger.has("epmapper_rpc") {
        steps.push("Enumerate RPC interfaces and pivot through IPC$ (SAMR/SVCCTL/LSARPC) for domain-wide compromise");
    }
    if ledger.has("spoolss_pipe") {
        steps.push("Abuse Print Spooler RPC (PrintNightmare / coerced authentication) for SYSTEM or relay");
    }
    if ledger.has("no_signing") && (ledger.has("ntlm_info") || ledger.has("nbns_dc")) {
        steps.push("Coerce NTLM authentication to this host (PetitPotam / PrinterBug) and relay without signing");
    }
    if ledger.has("ms17_010") {
        steps.push("Exploit MS17-010 (EternalBlue) — Trans2 oracle indicates likely unpatched kernel path");
    }
    if ledger.has("petitpotam_surface") || (ledger.has("efsrpc_pipe") && ledger.has("no_signing")) {
        steps.push("Coerce domain authentication via EFSRPC (PetitPotam) and relay without SMB signing");
    }
    if ledger.has("zerologon_surface") || (ledger.has("netlogon_pipe") && ledger.has("nbns_dc")) {
        steps.push("Reset domain-controller secure channel via Zerologon-class Netlogon RPC abuse");
    }
    if ledger.has("printnightmare_surface") || (ledger.has("spoolss_pipe") && ledger.has("no_signing")) {
        steps.push("Achieve SYSTEM or relay via Print Spooler RPC without SMB signing");
    }
    if ledger.has("admin_share_open") {
        steps.push("Harvest secrets from accessible hidden admin shares (C$ / ADMIN$) via null session");
    }
    if ledger.has("eol_os") {
        steps.push("Leverage unpatched End-of-Life Windows vulnerabilities");
    }
    let critical_like = ledger.has("smbv1") || ledger.has("smbghost") || ledger.has("ms17_010") || ledger.has("admin_share_open") || ledger.has("zerologon_surface") || ledger.has("printnightmare_surface");
    let relay_takeover = ledger.has("no_signing")
        && (ledger.has("anonymous_ipc")
            || ledger.has("spoolss_pipe")
            || ledger.has("nbns_dc")
            || ledger.has("epmapper_rpc")
            || ledger.has("petitpotam_surface")
            || ledger.has("efsrpc_pipe")
            || ledger.has("printnightmare_surface"));
    if steps.len() < 2 || (!critical_like && !relay_takeover) {
        return None;
    }
    let step_strings: Vec<String> = steps.iter().map(|s| (*s).to_string()).collect();
    let nodes = json!([
        { "id": "internet", "label": "Network position", "kind": "source" },
        { "id": host, "label": host, "kind": "smb-host" },
        { "id": "domain", "label": "Windows domain", "kind": "impact" }
    ]);
    let edges: Vec<Value> = steps
        .iter()
        .enumerate()
        .map(|(i, s)| json!({ "from": "internet", "to": host, "type": "exploit", "step": i + 1, "action": s }))
        .collect();
    let ev = Evidence::new()
        .with("host", host)
        .with("attack_path_steps", json!(step_strings))
        .with("graph", json!({ "nodes": nodes, "edges": edges }))
        .check("toxic_combination", true, "multiple high-impact SMB weaknesses observed on one host");
    let mut f = finding_rich(
        ENGINE_ID,
        "SMB ransomware / lateral-movement attack path",
        "critical",
        "T1210",
        "The observed SMB weaknesses combine into a concrete takeover path used by real ransomware crews: remote code execution and/or credential relay against an exposed, weakly-configured SMB host, leading to domain-wide propagation. Remediate the critical items first — disabling SMBv1 and requiring SMB signing breaks the chain.",
        target,
        0.9,
        ev,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("category".to_string(), json!("attack_path"));
        obj.insert("attack_path".to_string(), json!(step_strings));
    }
    Some(f)
}

/// CLI shim (`fingerprint_engine smb_netbios <target>`): runs with default parameters.
pub async fn run_smb_netbios(target: &str) {
    let ctx = EngineRunContext::default();
    print_result(run_smb_netbios_result(target, &ctx).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nbss_wrap_encodes_24bit_length() {
        let w = nbss_wrap(&[0xAA; 5]);
        assert_eq!(w[0], 0x00);
        assert_eq!(&w[1..4], &[0x00, 0x00, 0x05]);
        assert_eq!(w.len(), 9);
    }

    #[test]
    fn smb2_negotiate_is_well_formed() {
        let pkt = build_smb2_negotiate(false);
        // NBSS header then SMB2 magic.
        assert_eq!(pkt[0], 0x00);
        assert_eq!(&pkt[4..8], &[0xFE, b'S', b'M', b'B']);
        // SMB2 NEGOTIATE *request* body order: StructureSize, DialectCount, SecurityMode, …
        let body = &pkt[4 + 64..];
        assert_eq!(u16::from_le_bytes([body[0], body[1]]), 36); // StructureSize
        assert_eq!(u16::from_le_bytes([body[2], body[3]]), 4); // DialectCount
        assert_eq!(u16::from_le_bytes([body[4], body[5]]), 0x0001); // SecurityMode = SIGNING_ENABLED
    }

    #[test]
    fn smb2_negotiate_311_includes_contexts() {
        let pkt = build_smb2_negotiate(true);
        let body = &pkt[4 + 64..];
        assert_eq!(u16::from_le_bytes([body[2], body[3]]), 5); // DialectCount: 5 incl 3.1.1
        // NegotiateContextCount lives in the trailing 8 bytes of the 36-byte fixed body.
        let ctx_count = u16::from_le_bytes([body[32], body[33]]);
        assert_eq!(ctx_count, 2);
    }

    fn synth_negotiate_response(dialect: u16, security_mode: u16) -> Vec<u8> {
        let mut smb = vec![0xFEu8, b'S', b'M', b'B'];
        smb.extend_from_slice(&64u16.to_le_bytes()); // structure size
        smb.extend_from_slice(&0u16.to_le_bytes()); // credit charge
        smb.extend_from_slice(&0u32.to_le_bytes()); // status = 0
        smb.extend_from_slice(&0u16.to_le_bytes()); // command = NEGOTIATE
        smb.extend_from_slice(&1u16.to_le_bytes()); // credit
        smb.extend_from_slice(&1u32.to_le_bytes()); // flags = response
        smb.extend_from_slice(&0u32.to_le_bytes()); // next command
        smb.extend_from_slice(&0u64.to_le_bytes()); // message id
        smb.extend_from_slice(&0u32.to_le_bytes()); // reserved
        smb.extend_from_slice(&0u32.to_le_bytes()); // tree id
        smb.extend_from_slice(&0u64.to_le_bytes()); // session id
        smb.extend_from_slice(&[0u8; 16]); // signature
        // body (64 bytes)
        let mut body = Vec::new();
        body.extend_from_slice(&65u16.to_le_bytes()); // StructureSize
        body.extend_from_slice(&security_mode.to_le_bytes());
        body.extend_from_slice(&dialect.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // context count
        body.extend_from_slice(&[0u8; 16]); // server guid
        body.extend_from_slice(&0u32.to_le_bytes()); // capabilities
        body.extend_from_slice(&0u32.to_le_bytes()); // max transact
        body.extend_from_slice(&0u32.to_le_bytes()); // max read
        body.extend_from_slice(&0u32.to_le_bytes()); // max write
        body.extend_from_slice(&0u64.to_le_bytes()); // system time
        body.extend_from_slice(&0u64.to_le_bytes()); // boot time
        body.extend_from_slice(&0u16.to_le_bytes()); // sec buf offset
        body.extend_from_slice(&0u16.to_le_bytes()); // sec buf len
        body.extend_from_slice(&0u32.to_le_bytes()); // negotiate context offset
        smb.extend_from_slice(&body);
        nbss_wrap(&smb)
    }

    #[test]
    fn parses_smb2_negotiate_and_signing() {
        let resp = synth_negotiate_response(0x0311, 0x0003); // enabled + required
        let neg = parse_smb2_negotiate(&resp).expect("parse");
        assert_eq!(neg.dialect, 0x0311);
        assert!(signing_enabled(&neg));
        assert!(signing_required(&neg));
        assert_eq!(dialect_name(neg.dialect), "SMB 3.1.1");

        let resp2 = synth_negotiate_response(0x0210, 0x0001); // enabled, not required
        let neg2 = parse_smb2_negotiate(&resp2).expect("parse");
        assert!(signing_enabled(&neg2));
        assert!(!signing_required(&neg2));
    }

    #[test]
    fn smb1_acceptance_detection() {
        // Build a minimal SMB1 negotiate response: header + WordCount + DialectIndex 0.
        let mut smb = vec![0xFFu8, b'S', b'M', b'B', 0x72];
        smb.extend_from_slice(&0u32.to_le_bytes()); // status
        smb.resize(32, 0); // pad header to 32 bytes
        smb.push(0x11); // WordCount = 17
        smb.extend_from_slice(&0u16.to_le_bytes()); // DialectIndex = 0 (accepted)
        let resp = nbss_wrap(&smb);
        assert!(smb1_negotiate_accepted(&resp));

        // DialectIndex 0xFFFF => not accepted.
        let mut smb2 = vec![0xFFu8, b'S', b'M', b'B', 0x72];
        smb2.extend_from_slice(&0u32.to_le_bytes());
        smb2.resize(32, 0);
        smb2.push(0x01);
        smb2.extend_from_slice(&0xFFFFu16.to_le_bytes());
        assert!(!smb1_negotiate_accepted(&nbss_wrap(&smb2)));
    }

    fn av_pair(id: u16, s: &str) -> Vec<u8> {
        let utf16: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&(utf16.len() as u16).to_le_bytes());
        out.extend_from_slice(&utf16);
        out
    }

    #[test]
    fn parses_ntlm_challenge_targetinfo() {
        // Construct a type-2 message: signature + type + targetname fields + flags + challenge +
        // reserved + targetinfo fields + version + [targetinfo blob].
        let mut av = Vec::new();
        av.extend_from_slice(&av_pair(1, "FILESERVER")); // NetBIOS computer
        av.extend_from_slice(&av_pair(2, "CORP")); // NetBIOS domain
        av.extend_from_slice(&av_pair(3, "fileserver.corp.local")); // DNS computer
        av.extend_from_slice(&av_pair(4, "corp.local")); // DNS domain
        av.extend_from_slice(&[0, 0, 0, 0]); // MsvAvEOL

        let target_name = "CORP".encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<u8>>();
        let header_len = 56u32; // up to end of version
        let tn_off = header_len;
        let ti_off = header_len + target_name.len() as u32;

        let mut msg = Vec::new();
        msg.extend_from_slice(b"NTLMSSP\x00");
        msg.extend_from_slice(&2u32.to_le_bytes()); // type 2
        msg.extend_from_slice(&(target_name.len() as u16).to_le_bytes()); // tn len
        msg.extend_from_slice(&(target_name.len() as u16).to_le_bytes()); // tn maxlen
        msg.extend_from_slice(&tn_off.to_le_bytes()); // tn offset
        msg.extend_from_slice(&0x0200_0000u32.to_le_bytes()); // flags: NEGOTIATE_VERSION
        msg.extend_from_slice(&[0u8; 8]); // server challenge
        msg.extend_from_slice(&[0u8; 8]); // reserved
        msg.extend_from_slice(&(av.len() as u16).to_le_bytes()); // ti len
        msg.extend_from_slice(&(av.len() as u16).to_le_bytes()); // ti maxlen
        msg.extend_from_slice(&ti_off.to_le_bytes()); // ti offset
        msg.extend_from_slice(&[10u8, 0, 0x40, 0x4f, 0, 0, 0, 0x0f]); // version 10.0.20288
        msg.extend_from_slice(&target_name);
        msg.extend_from_slice(&av);

        let info = parse_ntlm_challenge(&msg).expect("parse ntlm");
        assert_eq!(info.netbios_computer.as_deref(), Some("FILESERVER"));
        assert_eq!(info.netbios_domain.as_deref(), Some("CORP"));
        assert_eq!(info.dns_computer.as_deref(), Some("fileserver.corp.local"));
        assert_eq!(info.dns_domain.as_deref(), Some("corp.local"));
        assert_eq!(info.os_version, Some((10, 0, 0x4f40)));
    }

    #[test]
    fn windows_release_flags_eol() {
        assert!(windows_release((6, 1, 7601)).1); // Win7/2008R2 EoL
        assert!(!windows_release((10, 0, 19045)).1); // Win10 supported
        assert!(windows_release((5, 1, 2600)).1); // XP EoL
    }

    #[test]
    fn nbns_query_is_wildcard_nbstat() {
        let q = build_nbns_node_status();
        assert_eq!(q[12], 0x20); // name length 32
        assert!(q.windows(4).any(|w| w == b"CKAA"));
        // QTYPE NBSTAT (0x0021) at the end.
        let n = q.len();
        assert_eq!(&q[n - 4..n - 2], &[0x00, 0x21]);
    }

    #[test]
    fn utf16_decoder_trims_nuls() {
        let b: Vec<u8> = "AB".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(utf16le_to_string(&b), "AB");
    }

    #[test]
    fn attack_path_requires_critical_chain() {
        let mut l = Ledger::default();
        l.add("smb_reachable", "medium");
        l.add("no_signing", "high");
        // no critical-like (smbv1/smbghost) yet → no path
        assert!(synthesize_attack_path(&l, "t", "h").is_none());
        l.add("smbv1", "critical");
        let ap = synthesize_attack_path(&l, "t", "h").expect("path");
        assert_eq!(ap["severity"], json!("critical"));
    }

    #[test]
    fn dce_rpc_bind_ack_detection() {
        let bind_ack = vec![5, 0, 12, 0x03, 0x10, 0, 0, 0, 0x30, 0, 0, 0, 1, 0, 0, 0];
        assert!(dce_rpc_is_bind_ack(&bind_ack));
        assert!(!dce_rpc_is_bind_ack(&[5, 0, 11, 0x03]));
    }

    #[test]
    fn nbns_role_classifies_dc_suffix() {
        let names = vec!["CORPDC<1C>".to_string(), "WORKSTATION<00>".to_string()];
        let roles = classify_nbns_roles(&names);
        assert_eq!(roles.len(), 2);
        assert!(roles.iter().any(|(n, r)| n == "CORPDC" && *r == "Domain Controller"));
    }

    #[test]
    fn posture_score_caps_at_100() {
        let mut l = Ledger::default();
        for _ in 0..5 {
            l.add("smbv1", "critical");
        }
        assert_eq!(posture_score(&l), 100);
        assert_eq!(posture_grade(100), "F");
    }

    #[test]
    fn spnego_detects_kerberos_oid() {
        let blob = vec![
            0x60, 0x82, 0x01, 0x00, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, 0xA0, 0x82,
            0x01, 0x00, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02,
        ];
        let mechs = detect_spnego_mechanisms(&blob);
        assert!(mechs.contains(&"Kerberos"));
    }

    #[test]
    fn attack_path_relay_chain_without_smbv1() {
        let mut l = Ledger::default();
        l.add("no_signing", "high");
        l.add("anonymous_ipc", "high");
        l.add("spoolss_pipe", "high");
        let ap = synthesize_attack_path(&l, "t", "h").expect("relay path");
        assert_eq!(ap["category"], json!("attack_path"));
    }

    #[test]
    fn exposure_graph_links_ipc_to_pipes() {
        let mut l = Ledger::default();
        l.add("anonymous_ipc", "high");
        l.add("spoolss_pipe", "high");
        let g = build_exposure_graph("host", &l);
        assert!(g["nodes"].as_array().unwrap().len() >= 3);
    }

    #[test]
    fn session_setup_guest_flag_parsed() {
        let mut resp = vec![0u8; 4];
        resp.extend_from_slice(&[0xFE, b'S', b'M', b'B']);
        resp.resize(4 + 64 + 4, 0);
        resp[4 + 64 + 2] = 0x01; // IS_GUEST
        assert!(parse_session_setup_guest(&resp));
        resp[4 + 64 + 2] = 0x00;
        assert!(!parse_session_setup_guest(&resp));
    }

    #[test]
    fn mac_oui_vendor_matches_dell() {
        assert_eq!(mac_oui_vendor("00:14:22:AB:CD:EF"), Some("Dell"));
        assert_eq!(mac_oui_vendor("005056abc123"), Some("VMware"));
    }

    #[test]
    fn zerologon_surface_requires_dc_and_netlogon() {
        let mut l = Ledger::default();
        l.add("netlogon_pipe", "high");
        assert!(synthesize_zerologon_surface(&l, "t", "h").is_none());
        l.add("nbns_dc", "high");
        let z = synthesize_zerologon_surface(&l, "t", "h").expect("zerologon");
        assert_eq!(z["severity"], json!("critical"));
    }

    #[test]
    fn printnightmare_surface_requires_spoolss_and_no_signing() {
        let mut l = Ledger::default();
        l.add("spoolss_pipe", "high");
        assert!(synthesize_printnightmare_surface(&l, "t", "h").is_none());
        l.add("no_signing", "high");
        let p = synthesize_printnightmare_surface(&l, "t", "h").expect("printnightmare");
        assert_eq!(p["category"], json!("attack_path"));
    }

    #[test]
    fn compliance_gaps_include_iso27001() {
        let mut l = Ledger::default();
        l.add("no_signing", "high");
        let gaps = compliance_gaps(&l);
        assert!(gaps["iso_27001"].as_array().unwrap().len() >= 1);
    }
}
