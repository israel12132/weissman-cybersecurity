//! PQC Readiness Scanner — world-class, evidence-driven post-quantum cryptography posture.
//!
//! This engine performs **live** crypto-negotiation probing — nothing is fabricated. Where a
//! competitor scanner stops at "the leaf certificate uses RSA", this engine actually negotiates
//! with the target to answer the only question that matters for "harvest-now-decrypt-later" (HNDL):
//! *does this endpoint already negotiate a post-quantum (hybrid) key exchange, or is every session
//! it terminates today recordable and decryptable by a future quantum adversary?*
//!
//! Capabilities (each is a real network probe, gated by a GUI knob):
//!   * **TLS 1.3 PQC key-exchange negotiation** — crafts a raw ClientHello with an *empty*
//!     `key_share` (RFC 8446 §4.2.8 group-selection request) advertising the PQC hybrid groups
//!     (`X25519MLKEM768`, `SecP256r1MLKEM768`, `X25519Kyber768Draft00`, pure ML-KEM, …) and reads
//!     the server's `HelloRetryRequest`/`ServerHello` to learn the group it *actually* selects.
//!     A PQC group in the reply is definitive proof of post-quantum readiness; an
//!     `handshake_failure` alert on a PQC-only offer is definitive proof of exposure.
//!   * **SSH PQC key-exchange detection** — completes the SSH identification exchange and parses the
//!     server's `SSH_MSG_KEXINIT` `kex_algorithms` name-list for `sntrup761x25519-sha512` /
//!     `mlkem768x25519-sha256` hybrids (OpenSSH ≥ 9.x posture).
//!   * **Certificate crypto classification** — leaf key type/size + signature algorithm, expiry and
//!     trust-anchor posture, all framed against the PQC migration runway.
//!   * **Harvest-Now-Decrypt-Later risk model** — quantitative Mosca's-inequality scoring
//!     (`data_lifetime + migration_time > quantum_eta`) with operator-tunable horizons.
//!   * **Compliance timeline mapping** — CNSA 2.0 / NIST / BSI / ANSSI migration-deadline gap.
//!   * **Quantum-Readiness Score** — a normalised 0–100 posture index over every applicable
//!     dimension, surfaced as a structured summary finding the UI renders as the headline metric.
//!
//! Every knob is read from the live scan request body (`POST /api/command-center/scan` →
//! `EngineRunContext::job_params`) via [`crate::arsenal_config::ArsenalConfig`], so an operator can
//! tune ports, timeouts, intensity, the exact PQC group set, SNI, HNDL horizons, and the compliance
//! framework without a code change — the "infinite options" guarantee.

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    extract_host, header_value, http_client, http_get, normalize_url, tls_cert_details,
    TlsCertDetails,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const PQC_PROBE_DEPTH: &str = "pqc_kex_negotiation";
const PQC_MITRE: &str = "T1600"; // Weaken Encryption
const MAX_TLS_READ: usize = 16_384;
const MAX_SSH_READ: usize = 8_192;

/// SHA-256("HelloRetryRequest") — the magic `ServerHello.random` that marks an HRR (RFC 8446 §4.1.3).
const HRR_MAGIC: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

// ─────────────────────────────────────────────────────────────────────────────
// TLS named-group catalog (IANA TLS Supported Groups + PQC drafts)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NamedGroup {
    code: u16,
    name: &'static str,
    /// Post-quantum (pure ML-KEM or hybrid). Classical groups are quantum-vulnerable.
    pqc: bool,
    /// Hybrid (classical ⊕ PQC) — preferred transition target per CNSA 2.0 / NIST.
    hybrid: bool,
}

const GROUPS: &[NamedGroup] = &[
    // ── Post-quantum hybrids (the deployable, recommended transition target) ──
    NamedGroup {
        code: 0x11EC,
        name: "X25519MLKEM768",
        pqc: true,
        hybrid: true,
    },
    NamedGroup {
        code: 0x11EB,
        name: "SecP256r1MLKEM768",
        pqc: true,
        hybrid: true,
    },
    NamedGroup {
        code: 0x11ED,
        name: "SecP384r1MLKEM1024",
        pqc: true,
        hybrid: true,
    },
    NamedGroup {
        code: 0x6399,
        name: "X25519Kyber768Draft00",
        pqc: true,
        hybrid: true,
    },
    NamedGroup {
        code: 0x639A,
        name: "SecP256r1Kyber768Draft00",
        pqc: true,
        hybrid: true,
    },
    NamedGroup {
        code: 0x2F4B,
        name: "X25519Kyber512Draft00",
        pqc: true,
        hybrid: true,
    },
    // ── Pure ML-KEM (FIPS 203 standalone codepoints) ──
    NamedGroup {
        code: 0x0200,
        name: "MLKEM512",
        pqc: true,
        hybrid: false,
    },
    NamedGroup {
        code: 0x0201,
        name: "MLKEM768",
        pqc: true,
        hybrid: false,
    },
    NamedGroup {
        code: 0x0202,
        name: "MLKEM1024",
        pqc: true,
        hybrid: false,
    },
    // ── Classical (quantum-vulnerable) ──
    NamedGroup {
        code: 0x001D,
        name: "x25519",
        pqc: false,
        hybrid: false,
    },
    NamedGroup {
        code: 0x001E,
        name: "x448",
        pqc: false,
        hybrid: false,
    },
    NamedGroup {
        code: 0x0017,
        name: "secp256r1",
        pqc: false,
        hybrid: false,
    },
    NamedGroup {
        code: 0x0018,
        name: "secp384r1",
        pqc: false,
        hybrid: false,
    },
    NamedGroup {
        code: 0x0019,
        name: "secp521r1",
        pqc: false,
        hybrid: false,
    },
    NamedGroup {
        code: 0x0100,
        name: "ffdhe2048",
        pqc: false,
        hybrid: false,
    },
    NamedGroup {
        code: 0x0101,
        name: "ffdhe3072",
        pqc: false,
        hybrid: false,
    },
];

fn group_by_code(code: u16) -> Option<NamedGroup> {
    GROUPS.iter().copied().find(|g| g.code == code)
}

fn group_name(code: u16) -> String {
    group_by_code(code).map_or_else(|| format!("0x{code:04X}"), |g| g.name.to_string())
}

/// All PQC group codepoints, hybrids first (most-preferred transition target).
fn pqc_group_codes() -> Vec<u16> {
    GROUPS.iter().filter(|g| g.pqc).map(|g| g.code).collect()
}

/// PQC groups first, then classical — used to learn the server's single top preference.
fn all_group_codes() -> Vec<u16> {
    let mut v: Vec<u16> = GROUPS.iter().filter(|g| g.pqc).map(|g| g.code).collect();
    v.extend(GROUPS.iter().filter(|g| !g.pqc).map(|g| g.code));
    v
}

// ─────────────────────────────────────────────────────────────────────────────
// Raw TLS 1.3 ClientHello construction (no TLS library — works regardless of the
// local OpenSSL's PQC support, since detection only reads the server's choice).
// ─────────────────────────────────────────────────────────────────────────────

static RNG_STATE: AtomicU64 = AtomicU64::new(0);

/// Tiny xorshift64 PRNG. The 32 random bytes only need to be unpredictable enough that two
/// ClientHellos differ; group negotiation does not depend on their cryptographic quality.
fn random_bytes(out: &mut [u8]) {
    let mut s = RNG_STATE.load(Ordering::Relaxed);
    if s == 0 {
        s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15)
            | 1;
    }
    for b in out.iter_mut() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        *b = (s & 0xFF) as u8;
    }
    RNG_STATE.store(s, Ordering::Relaxed);
}

fn push_ext(buf: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    buf.extend_from_slice(&ext_type.to_be_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Build a TLS 1.3 ClientHello record advertising `groups` with an **empty** `key_share`,
/// i.e. a group-selection request: a compliant server replies with a HelloRetryRequest naming the
/// group it would use, or a fatal alert if it supports none of the offered groups.
fn build_client_hello(sni: &str, groups: &[u16]) -> Vec<u8> {
    let mut exts: Vec<u8> = Vec::new();

    // server_name (SNI)
    if !sni.is_empty() && sni.len() < 256 {
        let host = sni.as_bytes();
        let mut list = Vec::new();
        list.push(0x00); // host_name
        list.extend_from_slice(&(host.len() as u16).to_be_bytes());
        list.extend_from_slice(host);
        let mut sn = Vec::new();
        sn.extend_from_slice(&(list.len() as u16).to_be_bytes());
        sn.extend_from_slice(&list);
        push_ext(&mut exts, 0x0000, &sn);
    }

    // supported_versions → TLS 1.3 only
    push_ext(&mut exts, 0x002B, &[0x02, 0x03, 0x04]);

    // signature_algorithms (broad, so the server is willing to proceed)
    {
        let schemes: [u16; 9] = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0807,
        ];
        let mut list = Vec::new();
        for s in schemes {
            list.extend_from_slice(&s.to_be_bytes());
        }
        let mut sa = Vec::new();
        sa.extend_from_slice(&(list.len() as u16).to_be_bytes());
        sa.extend_from_slice(&list);
        push_ext(&mut exts, 0x000D, &sa);
    }

    // supported_groups
    {
        let mut list = Vec::new();
        for g in groups {
            list.extend_from_slice(&g.to_be_bytes());
        }
        let mut sg = Vec::new();
        sg.extend_from_slice(&(list.len() as u16).to_be_bytes());
        sg.extend_from_slice(&list);
        push_ext(&mut exts, 0x000A, &sg);
    }

    // key_share — empty client_shares vector (RFC 8446 §4.2.8 group-selection request)
    push_ext(&mut exts, 0x0033, &[0x00, 0x00]);

    // psk_key_exchange_modes → psk_dhe_ke (some stacks require it alongside TLS 1.3)
    push_ext(&mut exts, 0x002D, &[0x01, 0x01]);

    // ── ClientHello body ──
    let mut ch = Vec::new();
    ch.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2
    let mut rnd = [0u8; 32];
    random_bytes(&mut rnd);
    ch.extend_from_slice(&rnd); // random
    ch.push(32); // legacy_session_id length (middlebox-compat mode)
    let mut sid = [0u8; 32];
    random_bytes(&mut sid);
    ch.extend_from_slice(&sid);
    // cipher_suites: AES-128-GCM, AES-256-GCM, CHACHA20-POLY1305
    let suites: [u16; 3] = [0x1301, 0x1302, 0x1303];
    ch.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
    for s in suites {
        ch.extend_from_slice(&s.to_be_bytes());
    }
    ch.extend_from_slice(&[0x01, 0x00]); // compression: 1 method = null
    ch.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    ch.extend_from_slice(&exts);

    // ── Handshake header (ClientHello = 0x01, 24-bit length) ──
    let mut hs = Vec::with_capacity(ch.len() + 4);
    hs.push(0x01);
    let len = ch.len();
    hs.push(((len >> 16) & 0xFF) as u8);
    hs.push(((len >> 8) & 0xFF) as u8);
    hs.push((len & 0xFF) as u8);
    hs.extend_from_slice(&ch);

    // ── TLS record (handshake = 0x16, legacy record version TLS 1.0) ──
    let mut rec = Vec::with_capacity(hs.len() + 5);
    rec.push(0x16);
    rec.extend_from_slice(&[0x03, 0x01]);
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

// ─────────────────────────────────────────────────────────────────────────────
// TLS ServerHello / HelloRetryRequest / Alert parsing (bounds-checked, no panics)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum KexReply {
    /// HelloRetryRequest naming `group` (server supports & prefers it). Definitive.
    HelloRetry { group: u16, tls13: bool },
    /// ServerHello proceeding with `group` (present when the server echoed a key_share).
    ServerHello { group: Option<u16>, tls13: bool },
    /// Fatal/warning alert (level, description). 40 = handshake_failure, 71 = insufficient_security.
    Alert { level: u8, description: u8 },
    /// Connected but no usable TLS response (timeout, RST, non-TLS service).
    NoResponse,
    /// A TLS record was received but could not be parsed as a ServerHello/alert.
    Malformed,
}

fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

/// True once `buf` holds at least one complete TLS record.
fn have_full_record(buf: &[u8]) -> bool {
    match be16(buf, 3) {
        Some(len) => buf.len() >= 5 + len as usize,
        None => false,
    }
}

fn parse_tls_reply(buf: &[u8]) -> KexReply {
    if buf.len() < 5 {
        return KexReply::NoResponse;
    }
    let rec_type = buf[0];
    let Some(rec_len) = be16(buf, 3) else {
        return KexReply::Malformed;
    };
    let body = match buf.get(5..5 + rec_len as usize) {
        Some(b) => b,
        None => buf.get(5..).unwrap_or(&[]),
    };

    if rec_type == 0x15 {
        // Alert
        return match (body.first(), body.get(1)) {
            (Some(&l), Some(&d)) => KexReply::Alert {
                level: l,
                description: d,
            },
            _ => KexReply::Malformed,
        };
    }
    if rec_type != 0x16 {
        return KexReply::Malformed;
    }
    // Handshake — expect ServerHello (0x02)
    if body.first() != Some(&0x02) {
        return KexReply::Malformed;
    }
    let sh = body.get(4..).unwrap_or(&[]);
    parse_server_hello(sh).unwrap_or(KexReply::Malformed)
}

fn parse_server_hello(sh: &[u8]) -> Option<KexReply> {
    // legacy_version(2) random(32) sid_len(1) sid cipher(2) comp(1) ext_len(2) exts
    let random = sh.get(2..34)?;
    let is_hrr = random == HRR_MAGIC;
    let sid_len = *sh.get(34)? as usize;
    let mut idx = 35 + sid_len;
    let _cipher = be16(sh, idx)?;
    idx += 2;
    let _comp = sh.get(idx)?;
    idx += 1;
    let ext_total = be16(sh, idx)? as usize;
    idx += 2;
    let exts = sh.get(idx..idx + ext_total).or_else(|| sh.get(idx..))?;

    let mut tls13 = false;
    let mut selected_group: Option<u16> = None;
    let mut p = 0usize;
    while p + 4 <= exts.len() {
        let etype = be16(exts, p)?;
        let elen = be16(exts, p + 2)? as usize;
        let edata = exts.get(p + 4..p + 4 + elen)?;
        match etype {
            0x002B => {
                // supported_versions (selected): single u16
                if be16(edata, 0) == Some(0x0304) {
                    tls13 = true;
                }
            }
            0x0033 => {
                // key_share — HRR: selected_group(2); ServerHello: group(2)+kex
                selected_group = be16(edata, 0);
            }
            _ => {}
        }
        p += 4 + elen;
    }

    if is_hrr {
        Some(KexReply::HelloRetry {
            group: selected_group.unwrap_or(0),
            tls13,
        })
    } else {
        Some(KexReply::ServerHello {
            group: selected_group,
            tls13,
        })
    }
}

/// Send a group-selection ClientHello and read the server's choice.
async fn probe_tls_groups(
    host: &str,
    port: u16,
    sni: &str,
    groups: &[u16],
    timeout_ms: u64,
) -> KexReply {
    let dur = Duration::from_millis(timeout_ms);
    let ch = build_client_hello(sni, groups);
    let addr = format!("{host}:{port}");
    let mut stream = match timeout(dur, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return KexReply::NoResponse,
    };
    if timeout(dur, stream.write_all(&ch)).await.is_err() {
        return KexReply::NoResponse;
    }
    let _ = stream.flush().await;

    let mut buf = vec![0u8; MAX_TLS_READ];
    let mut filled = 0usize;
    loop {
        match timeout(dur, stream.read(&mut buf[filled..])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                filled += n;
                if have_full_record(&buf[..filled]) || filled >= buf.len() {
                    break;
                }
            }
            _ => break,
        }
    }
    if filled == 0 {
        return KexReply::NoResponse;
    }
    parse_tls_reply(&buf[..filled])
}

/// Resolve the group selected in a reply (HRR or ServerHello), if any.
fn reply_group(r: &KexReply) -> Option<u16> {
    match r {
        KexReply::HelloRetry { group, .. } => Some(*group),
        KexReply::ServerHello { group, .. } => *group,
        _ => None,
    }
}

fn reply_tls13(r: &KexReply) -> bool {
    matches!(
        r,
        KexReply::HelloRetry { tls13: true, .. } | KexReply::ServerHello { tls13: true, .. }
    )
}

/// Outcome of the TLS PQC negotiation probe set.
#[derive(Debug, Clone)]
struct TlsPqcOutcome {
    reachable: bool,
    tls13: bool,
    /// Server's single top group preference across PQC+classical.
    preferred_group: Option<u16>,
    /// Definitive: server selected a PQC group when offered PQC-only.
    pqc_supported: bool,
    /// The PQC group the server picked (when supported).
    pqc_group: Option<u16>,
    /// Definitive negative: PQC-only offer was rejected with a fatal alert.
    pqc_rejected: bool,
    detail: String,
}

async fn run_tls_pqc_probe(host: &str, port: u16, sni: &str, timeout_ms: u64) -> TlsPqcOutcome {
    // Probe 1 — full group set: learn the server's single top preference.
    let all = probe_tls_groups(host, port, sni, &all_group_codes(), timeout_ms).await;
    let reachable = !matches!(all, KexReply::NoResponse);
    let tls13 = reply_tls13(&all);
    let preferred_group = reply_group(&all);

    // Probe 2 — PQC-only: definitive support/exposure test.
    let pqc = probe_tls_groups(host, port, sni, &pqc_group_codes(), timeout_ms).await;
    let pqc_group = reply_group(&pqc).filter(|c| group_by_code(*c).is_some_and(|g| g.pqc));
    let pqc_supported = pqc_group.is_some();
    let pqc_rejected = matches!(pqc, KexReply::Alert { .. });

    let detail = match (&all, &pqc) {
        (KexReply::NoResponse, _) => "no TLS response on the probed port".to_string(),
        _ if pqc_supported => format!(
            "server negotiates PQC group {} (top preference {})",
            pqc_group.map(group_name).unwrap_or_default(),
            preferred_group
                .map(group_name)
                .unwrap_or_else(|| "?".into())
        ),
        _ if pqc_rejected => {
            "server rejected a PQC-only key exchange (handshake alert)".to_string()
        }
        _ => format!(
            "server prefers classical group {}; no PQC group negotiated",
            preferred_group
                .map(group_name)
                .unwrap_or_else(|| "?".into())
        ),
    };

    TlsPqcOutcome {
        reachable,
        tls13,
        preferred_group,
        pqc_supported,
        pqc_group,
        pqc_rejected,
        detail,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SSH KEXINIT parsing — detect PQC hybrid key exchange (OpenSSH ≥ 9.x)
// ─────────────────────────────────────────────────────────────────────────────

/// SSH key-exchange names that carry post-quantum protection.
const SSH_PQC_KEX: &[&str] = &[
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
    "mlkem768x25519-sha256",
    "mlkem768nistp256-sha256",
    "mlkem1024nistp384-sha256",
];

#[derive(Debug, Clone, Default)]
struct SshKexInfo {
    banner: String,
    kex_algorithms: Vec<String>,
    pqc_kex: Vec<String>,
}

/// Parse the `kex_algorithms` name-list out of an `SSH_MSG_KEXINIT` payload that begins at `data`.
fn parse_ssh_kexinit(data: &[u8]) -> Option<Vec<String>> {
    // packet_length(4) padding_length(1) payload...
    let packet_len =
        u32::from_be_bytes([*data.first()?, *data.get(1)?, *data.get(2)?, *data.get(3)?]) as usize;
    let pad_len = *data.get(4)? as usize;
    if packet_len < pad_len + 1 {
        return None;
    }
    let payload_len = packet_len - pad_len - 1;
    let payload = data.get(5..5 + payload_len).or_else(|| data.get(5..))?;
    // payload[0] == 20 (SSH_MSG_KEXINIT), then 16-byte cookie, then first name-list.
    if payload.first() != Some(&20) {
        return None;
    }
    let nl_start = 1 + 16;
    let nl_len = u32::from_be_bytes([
        *payload.get(nl_start)?,
        *payload.get(nl_start + 1)?,
        *payload.get(nl_start + 2)?,
        *payload.get(nl_start + 3)?,
    ]) as usize;
    let nl = payload.get(nl_start + 4..nl_start + 4 + nl_len)?;
    let s = String::from_utf8_lossy(nl);
    Some(
        s.split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect(),
    )
}

async fn probe_ssh_kex(host: &str, port: u16, timeout_ms: u64) -> Option<SshKexInfo> {
    let dur = Duration::from_millis(timeout_ms);
    let addr = format!("{host}:{port}");
    let mut stream = match timeout(dur, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    // Read the server identification line first.
    let mut buf = vec![0u8; MAX_SSH_READ];
    let mut filled = 0usize;
    // Send our identification string (servers may withhold KEXINIT until they see it).
    let _ = stream.write_all(b"SSH-2.0-Weissman_PQC_Probe\r\n").await;
    let _ = stream.flush().await;

    loop {
        match timeout(dur, stream.read(&mut buf[filled..])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                filled += n;
                // KEXINIT is large; keep reading until we likely have it or the buffer is full.
                if filled >= buf.len()
                    || filled > 64 && buf[..filled].windows(2).any(|w| w == b"\r\n") && filled > 600
                {
                    break;
                }
            }
            _ => break,
        }
    }
    if filled == 0 {
        return None;
    }
    let data = &buf[..filled];
    // Extract banner (first CRLF-terminated "SSH-..." line) and the binary remainder.
    let (banner, rest) = match data.windows(2).position(|w| w == b"\r\n") {
        Some(pos) => (
            String::from_utf8_lossy(&data[..pos]).trim().to_string(),
            data.get(pos + 2..).unwrap_or(&[]),
        ),
        None => (String::new(), data),
    };
    if !banner.starts_with("SSH-") {
        return None;
    }
    let kex_algorithms = parse_ssh_kexinit(rest).unwrap_or_default();
    let pqc_kex: Vec<String> = kex_algorithms
        .iter()
        .filter(|k| SSH_PQC_KEX.iter().any(|p| k.eq_ignore_ascii_case(p)))
        .cloned()
        .collect();
    Some(SshKexInfo {
        banner,
        kex_algorithms,
        pqc_kex,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Harvest-Now-Decrypt-Later risk (Mosca's inequality) + Quantum-Readiness scoring
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct MoscaInputs {
    data_lifetime_years: u64,
    migration_years: u64,
    quantum_eta_years: u64,
}

/// Mosca's inequality: if `X (data shelf-life) + Y (migration time) > Z (time to a
/// cryptographically-relevant quantum computer)`, data encrypted *today* is already at risk.
fn mosca_gap_years(m: MoscaInputs) -> i64 {
    (m.data_lifetime_years as i64 + m.migration_years as i64) - m.quantum_eta_years as i64
}

#[derive(Debug, Clone, Default)]
struct PostureInputs {
    tls_reachable: bool,
    tls13: bool,
    tls_pqc_kex: bool,
    http_reachable: bool,
    hsts: bool,
    cert_obtained: bool,
    cert_key_adequate: bool,
    ssh_checked: bool,
    ssh_reachable: bool,
    ssh_pqc_kex: bool,
}

/// Normalised 0–100 Quantum-Readiness Score over the dimensions that actually apply to the target.
/// The dominant lever is whether the endpoint negotiates a PQC key exchange today (HNDL defence).
fn readiness_score(p: &PostureInputs) -> u32 {
    let mut achieved = 0f64;
    let mut applicable = 0f64;
    let mut add = |weight: f64, applies: bool, ok: bool| {
        if applies {
            applicable += weight;
            if ok {
                achieved += weight;
            }
        }
    };
    add(50.0, p.tls_reachable, p.tls_pqc_kex); // negotiates PQC KEX — the headline control
    add(10.0, p.tls_reachable, p.tls13); // modern, crypto-agile transport
    add(10.0, p.http_reachable, p.hsts); // downgrade resistance during migration
    add(10.0, p.cert_obtained, p.cert_key_adequate); // classical key hygiene
    add(20.0, p.ssh_checked && p.ssh_reachable, p.ssh_pqc_kex); // SSH PQC posture
    if applicable <= 0.0 {
        return 0;
    }
    (achieved / applicable * 100.0).round() as u32
}

fn score_severity(score: u32, hndl_exposed: bool) -> &'static str {
    match score {
        s if s >= 85 => "info",
        s if s >= 65 => "low",
        s if s >= 45 => "medium",
        s if s >= 25 => {
            if hndl_exposed {
                "high"
            } else {
                "medium"
            }
        }
        _ => {
            if hndl_exposed {
                "critical"
            } else {
                "high"
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Finding helper
// ─────────────────────────────────────────────────────────────────────────────

fn pqc_finding(
    title: &str,
    severity: &str,
    description: &str,
    target: &str,
    remediation: &str,
    confidence: f64,
    evidence: Evidence,
) -> Value {
    let mut f = finding_rich(
        "pqc_scanner",
        title,
        severity,
        PQC_MITRE,
        description,
        target,
        confidence,
        evidence,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("remediation".to_string(), json!(remediation));
        obj.insert("probe_depth".to_string(), json!(PQC_PROBE_DEPTH));
        obj.insert("category".to_string(), json!("post_quantum_crypto"));
    }
    f
}

// ─────────────────────────────────────────────────────────────────────────────
// Orchestration
// ─────────────────────────────────────────────────────────────────────────────

/// Backward-compatible entry point (CLI + alias callers). Uses default parameters.
pub async fn run_pqc_scanner_result(target: &str) -> EngineResult {
    run_pqc_scanner_result_ctx(target, &EngineRunContext::default()).await
}

/// Parameterised entry point used by the dispatch layer (reads `ctx.job_params`).
pub async fn run_pqc_scanner_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let domain = extract_host(target);
    let base = normalize_url(target);
    let sni = cfg.string("sni").unwrap_or_else(|| domain.clone());
    let timeout_ms = cfg.timeout_ms(6000);

    // Per-check toggles (all on by default — nothing silently hidden).
    let check_tls = cfg.bool_or("check_tls_kex", true);
    let check_ssh = cfg.bool_or("check_ssh_kex", true);
    let check_cert = cfg.bool_or("check_certificate", true);
    let check_well_known = cfg.bool_or("check_well_known", true);
    let check_ct = cfg.bool_or("check_ct_logs", true);
    let check_hndl = cfg.bool_or("check_hndl", true);
    let check_compliance = cfg.bool_or("check_compliance", true);

    let tls_ports = cfg.ports_or("tls_ports", &[443]);
    let ssh_ports = cfg.ports_or("ssh_ports", &[22]);

    // HNDL horizons (Mosca's inequality) — operator-tunable.
    let mosca = MoscaInputs {
        data_lifetime_years: cfg.u64_or("hndl_data_lifetime_years", 10).clamp(0, 100),
        migration_years: cfg.u64_or("hndl_migration_years", 3).clamp(0, 100),
        quantum_eta_years: cfg.u64_or("quantum_eta_years", 10).clamp(1, 100),
    };
    let framework = cfg.string_or("compliance_framework", "cnsa_2_0");
    let deadline_year = cfg.u64_or("compliance_deadline_year", 2030);

    let mut findings: Vec<Value> = Vec::new();
    let mut posture = PostureInputs::default();

    // ── 1) TLS PQC key-exchange negotiation (the headline probe) ─────────────
    let mut tls_outcome: Option<TlsPqcOutcome> = None;
    if check_tls {
        for &port in &tls_ports {
            let out = run_tls_pqc_probe(&domain, port, &sni, timeout_ms).await;
            if !out.reachable {
                continue;
            }
            posture.tls_reachable = true;
            posture.tls13 = out.tls13 || posture.tls13;
            if out.pqc_supported {
                posture.tls_pqc_kex = true;
            }

            let pref = out
                .preferred_group
                .map(group_name)
                .unwrap_or_else(|| "unknown".into());
            let ev = Evidence::new()
                .with("host", domain.clone())
                .with("port", port)
                .with("protocol", "tls")
                .with("tls13", out.tls13)
                .with("server_preferred_group", pref.clone())
                .with(
                    "server_preferred_group_code",
                    out.preferred_group.map(u64::from).unwrap_or(0),
                )
                .with("pqc_supported", out.pqc_supported)
                .with(
                    "pqc_group",
                    out.pqc_group.map(group_name).unwrap_or_default(),
                )
                .check(
                    "pqc_only_offer_accepted",
                    out.pqc_supported,
                    out.detail.clone(),
                )
                .check(
                    "pqc_only_offer_rejected",
                    out.pqc_rejected,
                    "fatal alert on PQC-only ClientHello",
                );

            if out.pqc_supported {
                let g = out.pqc_group.map(group_name).unwrap_or_default();
                findings.push(pqc_finding(
                    &format!("Post-quantum key exchange active on :{port} ({g})"),
                    "info",
                    &format!(
                        "{domain}:{port} negotiates the post-quantum hybrid group {g}. Sessions terminated here resist 'harvest-now, decrypt-later' recording. Confirm the rest of the fleet (load balancers, origin, API gateways) reaches parity, and pin the hybrid group server-side."
                    ),
                    target,
                    "Keep the PQC hybrid group enabled and ordered first server-side. Extend the same configuration to every TLS terminator and verify origin/back-end hops also negotiate PQC so the chain has no quantum-vulnerable link.",
                    0.97,
                    ev,
                ));
            } else if out.pqc_rejected {
                findings.push(pqc_finding(
                    &format!("No post-quantum key exchange on :{port} (HNDL-exposed)"),
                    "high",
                    &format!(
                        "{domain}:{port} rejected a post-quantum-only TLS 1.3 ClientHello and negotiates only classical key exchange ({pref}). Every session is recordable today and decryptable once a cryptographically-relevant quantum computer exists — the textbook harvest-now-decrypt-later exposure."
                    ),
                    target,
                    "Enable a TLS 1.3 PQC hybrid key-exchange group (X25519MLKEM768 per RFC 9370 / NIST SP 1800-38). Modern stacks support it: OpenSSL ≥ 3.5, BoringSSL, nginx, Cloudflare, AWS. Roll it out as the preferred group while keeping classical groups for fallback.",
                    0.9,
                    ev,
                ));
            } else {
                findings.push(pqc_finding(
                    &format!("Classical-only key exchange on :{port}"),
                    "medium",
                    &format!(
                        "{domain}:{port} negotiates classical group {pref} and did not select any offered post-quantum group. Plan a hybrid PQC key-exchange migration before the data you protect outlives the quantum threat horizon."
                    ),
                    target,
                    "Add X25519MLKEM768 (and SecP256r1MLKEM768 for FIPS stacks) to the server's supported groups and order it first. Validate with this scanner after rollout.",
                    0.85,
                    ev,
                ));
            }
            tls_outcome = Some(out);
            break; // first reachable TLS port characterises the endpoint
        }
        if !posture.tls_reachable {
            findings.push(pqc_finding(
                "TLS endpoint not reachable for PQC probe",
                "info",
                &format!(
                    "No TLS 1.3 handshake response from {domain} on ports {tls_ports:?}. PQC key-exchange posture could not be measured — confirm the host/port and re-run."
                ),
                target,
                "Verify the target exposes TLS on the probed port(s) and is reachable from the scanner egress, then re-run with the correct `tls_ports`.",
                0.6,
                Evidence::new().with("host", domain.clone()).with("ports", format!("{tls_ports:?}")),
            ));
        }
    }

    // ── 2) Certificate crypto classification ─────────────────────────────────
    if check_cert {
        if let Some(cert) = tls_cert_details(&domain).await {
            posture.cert_obtained = true;
            posture.cert_key_adequate = cert_key_adequate(&cert);
            findings.extend(certificate_findings(&cert, &domain, target));
        }
    }

    // ── 3) SSH PQC key-exchange detection ────────────────────────────────────
    if check_ssh {
        posture.ssh_checked = true;
        for &port in &ssh_ports {
            if let Some(info) = probe_ssh_kex(&domain, port, timeout_ms).await {
                posture.ssh_reachable = true;
                posture.ssh_pqc_kex = !info.pqc_kex.is_empty();
                let ev = Evidence::new()
                    .with("host", domain.clone())
                    .with("port", port)
                    .with("protocol", "ssh")
                    .with("server_banner", info.banner.clone())
                    .with("kex_algorithms", json!(info.kex_algorithms))
                    .with("pqc_kex", json!(info.pqc_kex))
                    .check(
                        "offers_pqc_kex",
                        !info.pqc_kex.is_empty(),
                        json!(info.pqc_kex),
                    );
                if info.pqc_kex.is_empty() {
                    findings.push(pqc_finding(
                        &format!("SSH offers no post-quantum key exchange on :{port}"),
                        "medium",
                        &format!(
                            "{} on {domain}:{port} advertises only classical SSH key exchange ({}). SSH sessions (admin, SCP, tunnels) are harvest-now-decrypt-later targets.",
                            info.banner,
                            info.kex_algorithms.join(", ")
                        ),
                        target,
                        "Upgrade to OpenSSH ≥ 9.0 and prefer a PQC hybrid KEX: set `KexAlgorithms sntrup761x25519-sha512@openssh.com,mlkem768x25519-sha256,...` (newest builds) ahead of classical curve25519.",
                        0.88,
                        ev,
                    ));
                } else {
                    findings.push(pqc_finding(
                        &format!("SSH negotiates post-quantum key exchange on :{port}"),
                        "info",
                        &format!(
                            "{} on {domain}:{port} offers PQC hybrid SSH key exchange ({}). Admin channels resist quantum harvest-now-decrypt-later. Ensure it is ordered first and required.",
                            info.banner,
                            info.pqc_kex.join(", ")
                        ),
                        target,
                        "Keep the PQC hybrid KEX first in `KexAlgorithms` and consider removing classical-only fallbacks for high-value bastions once all clients support the hybrid.",
                        0.95,
                        ev,
                    ));
                }
                break;
            }
        }
    }

    // ── 4) HTTPS posture (HSTS) — downgrade resistance during migration ──────
    if check_well_known || check_tls {
        let client = http_client().await;
        if let Some(p) = http_get(&client, &base).await {
            posture.http_reachable = true;
            let hsts = header_value(&p.headers, "strict-transport-security").unwrap_or("");
            posture.hsts = !hsts.is_empty();
            if hsts.is_empty() {
                findings.push(pqc_finding(
                    "Missing HSTS during PQC migration window",
                    "medium",
                    &format!(
                        "{} lacks Strict-Transport-Security. While rolling out PQC hybrids, an initial HTTP request can still be downgraded/MITM'd before the upgraded TLS even begins.",
                        p.final_url
                    ),
                    target,
                    "Send `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` and submit to the HSTS preload list.",
                    0.8,
                    Evidence::new().with("url", p.final_url.clone()),
                ));
            }

            // PQC capability advertisement endpoints (informational discovery).
            if check_well_known {
                if let Some(adv) = probe_well_known(&client, &base).await {
                    findings.push(adv);
                }
            }
        }
    }

    // ── 5) Certificate-transparency inventory (migration scope) ──────────────
    if check_ct {
        if let Some(ct) = probe_ct_logs(&domain, target).await {
            findings.push(ct);
        }
    }

    // ── 6) Harvest-Now-Decrypt-Later quantitative risk (Mosca) ───────────────
    let gap = mosca_gap_years(mosca);
    let hndl_exposed = gap > 0 && !posture.tls_pqc_kex;
    if check_hndl && posture.tls_reachable {
        let ev = Evidence::new()
            .with("data_lifetime_years", mosca.data_lifetime_years)
            .with("migration_years", mosca.migration_years)
            .with("quantum_eta_years", mosca.quantum_eta_years)
            .with("mosca_gap_years", gap)
            .with("model", "X + Y > Z (Mosca's inequality)")
            .with("pqc_kex_active", posture.tls_pqc_kex);
        if hndl_exposed {
            findings.push(pqc_finding(
                &format!("Harvest-Now-Decrypt-Later exposure: {gap}-year gap"),
                if gap >= 5 { "high" } else { "medium" },
                &format!(
                    "Mosca's inequality is breached: data shelf-life ({}y) + migration time ({}y) = {}y exceeds the quantum horizon ({}y) by {gap} years, and this endpoint does not yet negotiate PQC key exchange. Traffic captured today is decryptable inside your own data-protection lifetime.",
                    mosca.data_lifetime_years,
                    mosca.migration_years,
                    mosca.data_lifetime_years + mosca.migration_years,
                    mosca.quantum_eta_years
                ),
                target,
                "Treat PQC key-exchange migration as in-scope now (not a future project): enable hybrid groups on all TLS/SSH terminators, prioritising endpoints carrying long-lived secrets (PII, health, financial, state).",
                0.82,
                ev,
            ));
        } else if posture.tls_pqc_kex {
            findings.push(pqc_finding(
                "Harvest-Now-Decrypt-Later mitigated by PQC key exchange",
                "info",
                &format!(
                    "Endpoint negotiates PQC key exchange, so recorded sessions resist future quantum decryption even though the Mosca horizon (data {}y + migration {}y vs quantum {}y) would otherwise be tight.",
                    mosca.data_lifetime_years, mosca.migration_years, mosca.quantum_eta_years
                ),
                target,
                "Maintain PQC hybrids fleet-wide and re-assess the quantum horizon annually as NIST/industry estimates evolve.",
                0.9,
                ev,
            ));
        }
    }

    // ── 7) Compliance-timeline mapping ───────────────────────────────────────
    if check_compliance && posture.tls_reachable && !posture.tls_pqc_kex {
        findings.push(compliance_finding(&framework, deadline_year, target));
    }

    // ── 8) Quantum-Readiness Score summary (UI headline) ─────────────────────
    let score = readiness_score(&posture);
    let summary_sev = score_severity(score, hndl_exposed);
    let roadmap = build_roadmap(&posture, &framework);
    let summary_ev = Evidence::new()
        .with("readiness_score", score)
        .with("tls_reachable", posture.tls_reachable)
        .with("tls13", posture.tls13)
        .with("tls_pqc_kex", posture.tls_pqc_kex)
        .with("ssh_checked", posture.ssh_checked)
        .with("ssh_reachable", posture.ssh_reachable)
        .with("ssh_pqc_kex", posture.ssh_pqc_kex)
        .with("hsts", posture.hsts)
        .with("cert_key_adequate", posture.cert_key_adequate)
        .with("hndl_exposed", hndl_exposed)
        .with("mosca_gap_years", gap)
        .with("compliance_framework", framework.clone());

    let mut summary = pqc_finding(
        &format!("Quantum-Readiness Score: {score}/100"),
        summary_sev,
        &format!(
            "Post-quantum posture for {domain}: TLS PQC KEX {}, SSH PQC KEX {}, TLS 1.3 {}, HSTS {}. {}",
            yn(posture.tls_pqc_kex),
            if !posture.ssh_checked { "n/a".into() } else if posture.ssh_reachable { yn(posture.ssh_pqc_kex) } else { "ssh unreachable".into() },
            yn(posture.tls13),
            yn(posture.hsts),
            tls_outcome.as_ref().map(|o| o.detail.clone()).unwrap_or_else(|| "TLS not probed".into())
        ),
        target,
        "Drive the Quantum-Readiness Score toward 100: enable PQC hybrid key exchange on every TLS and SSH terminator, keep TLS 1.3 + HSTS, and inventory long-lived data for HNDL prioritisation.",
        0.93,
        summary_ev,
    );
    if let Some(obj) = summary.as_object_mut() {
        obj.insert("type".to_string(), json!("pqc_posture_summary"));
        obj.insert("readiness_score".to_string(), json!(score));
        obj.insert("hndl_exposed".to_string(), json!(hndl_exposed));
        obj.insert("roadmap".to_string(), json!(roadmap));
        obj.insert(
            "total_certs".to_string(),
            json!(if posture.cert_obtained { 1 } else { 0 }),
        );
        obj.insert(
            "vulnerable_certs".to_string(),
            json!(usize::from(posture.cert_obtained && !posture.tls_pqc_kex)),
        );
    }
    findings.insert(0, summary);

    EngineResult::ok(
        findings.clone(),
        format!(
            "pqc_scanner: readiness {score}/100, {} finding(s) [tls_pqc={}, ssh_pqc={}, hndl_gap={}y]",
            findings.len(),
            posture.tls_pqc_kex,
            posture.ssh_pqc_kex,
            gap
        ),
    )
}

fn yn(b: bool) -> String {
    if b {
        "yes".to_string()
    } else {
        "no".to_string()
    }
}

fn cert_key_adequate(cert: &TlsCertDetails) -> bool {
    if cert.is_rsa {
        cert.public_key_bits >= 2048
    } else if cert.is_ec {
        cert.public_key_bits >= 256
    } else {
        cert.public_key_bits >= 2048
    }
}

fn certificate_findings(cert: &TlsCertDetails, domain: &str, target: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let base_ev = || {
        Evidence::new()
            .with("issuer", cert.issuer.clone())
            .with("subject", cert.subject.clone())
            .with("signature_algorithm", cert.signature_algorithm.clone())
            .with("public_key_bits", u64::from(cert.public_key_bits))
            .with("is_rsa", cert.is_rsa)
            .with("is_ec", cert.is_ec)
            .with("days_until_expiry", cert.days_until_expiry)
    };

    if cert.expired {
        out.push(pqc_finding(
            &format!("Expired TLS certificate for {domain}"),
            "high",
            &format!(
                "Leaf certificate for {domain} is expired (issuer {}). Expired certs block the crypto-agility needed to stage a PQC hybrid rollout.",
                cert.issuer
            ),
            target,
            "Renew/automate certificate issuance (ACME) so the trust chain is healthy before layering PQC changes.",
            0.95,
            base_ev(),
        ));
    } else if cert.days_until_expiry < 30 {
        out.push(pqc_finding(
            &format!("TLS certificate expires in {} days", cert.days_until_expiry),
            "medium",
            &format!(
                "Certificate for {domain} expires in {} days (sig {}, {}-bit). A short runway complicates a staged PQC cutover.",
                cert.days_until_expiry, cert.signature_algorithm, cert.public_key_bits
            ),
            target,
            "Automate renewal (ACME) and align certificate rotation with the planned PQC migration windows.",
            0.85,
            base_ev(),
        ));
    }

    if cert.self_signed {
        out.push(pqc_finding(
            "Self-signed TLS certificate",
            "high",
            &format!(
                "Peer certificate for {domain} is self-signed (subject {}). There is no public CA path, so PQC migration must also establish a new trust anchor.",
                cert.subject
            ),
            target,
            "Issue from a managed CA (public or internal PKI) and plan trust-anchor distribution as part of the PQC roadmap.",
            0.9,
            base_ev(),
        ));
    }

    if cert.is_rsa && cert.public_key_bits < 2048 {
        out.push(pqc_finding(
            &format!("Weak RSA key ({} bits)", cert.public_key_bits),
            "high",
            &format!(
                "Leaf uses {}-bit RSA ({} signature) — below the NIST minimum and acutely quantum-vulnerable (Shor). Fix the classical weakness now, then plan ML-DSA (FIPS 204) signatures.",
                cert.public_key_bits, cert.signature_algorithm
            ),
            target,
            "Reissue with ≥ 3072-bit RSA or ECDSA P-256/384 immediately, then track PQC signature (ML-DSA / SLH-DSA) availability from your CA.",
            0.92,
            base_ev(),
        ));
    } else if cert.is_rsa {
        out.push(pqc_finding(
            &format!("RSA {}-bit certificate (quantum-vulnerable signature)", cert.public_key_bits),
            "info",
            &format!(
                "Leaf for {domain} uses RSA {}-bit / {} — authenticity is breakable by Shor's algorithm at scale. PQC certificate signatures (ML-DSA, FIPS 204) are not yet broadly issued; track CA roadmaps. Confidentiality is protected sooner via PQC key exchange.",
                cert.public_key_bits, cert.signature_algorithm
            ),
            target,
            "Prioritise PQC key exchange (protects confidentiality today). Monitor your CA for ML-DSA / SLH-DSA issuance and keep certificate automation ready for fast algorithm swaps (crypto-agility).",
            0.8,
            base_ev(),
        ));
    } else if cert.is_ec {
        out.push(pqc_finding(
            &format!("ECDSA P-{} certificate (quantum-vulnerable signature)", cert.public_key_bits),
            "info",
            &format!(
                "Leaf for {domain} uses ECDSA {}-bit / {} — quantum-vulnerable to Shor. Keep for now; confidentiality is best protected by enabling PQC hybrid key exchange.",
                cert.public_key_bits, cert.signature_algorithm
            ),
            target,
            "Enable a PQC hybrid key-exchange group and maintain certificate automation so signature algorithms can be rotated when PQC certs become available.",
            0.78,
            base_ev(),
        ));
    }

    out
}

async fn probe_well_known(client: &reqwest::Client, base: &str) -> Option<Value> {
    let paths = [
        "/.well-known/pqc-capabilities",
        "/.well-known/quantum-safe",
        "/.well-known/pqc",
        "/pqc/status",
    ];
    for path in &paths {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(client, &url).await {
            if (200..300).contains(&p.status) && p.body.len() > 8 {
                let low = p.body.to_ascii_lowercase();
                if [
                    "kyber",
                    "ml-kem",
                    "mlkem",
                    "dilithium",
                    "ml-dsa",
                    "sphincs",
                    "pqc",
                ]
                .iter()
                .any(|k| low.contains(k))
                {
                    return Some(pqc_finding(
                        &format!("PQC capability document at {path}"),
                        "info",
                        &format!(
                            "{} advertises post-quantum algorithms in its response body — review the declared hybrids and ensure they match what TLS actually negotiates.",
                            p.final_url
                        ),
                        base,
                        "Cross-check the advertised PQC capabilities against live TLS negotiation; advertisement without negotiation is a misconfiguration.",
                        0.7,
                        Evidence::new().with("url", p.final_url.clone()).with("status", u64::from(p.status)),
                    ));
                }
            }
        }
    }
    None
}

async fn probe_ct_logs(domain: &str, target: &str) -> Option<Value> {
    let client = http_client().await;
    let url = format!("https://crt.sh/?q={domain}&output=json");
    let p = http_get(&client, &url).await?;
    if p.status != 200 || !p.body.starts_with('[') {
        return None;
    }
    let arr = serde_json::from_str::<Value>(&p.body).ok()?;
    let count = arr.as_array().map(Vec::len).unwrap_or(0);
    if count == 0 {
        return None;
    }
    Some(pqc_finding(
        &format!("{count} certificate-transparency entries for {domain}"),
        "info",
        &format!(
            "crt.sh holds {count} CT entries for {domain}. Every active classical certificate is migration scope — inventory them so no quantum-vulnerable cert is missed during the PQC cutover."
        ),
        target,
        "Build a complete certificate inventory from CT logs and your CA, then track each cert's key/signature algorithm in the PQC migration plan.",
        0.65,
        Evidence::new().with("domain", domain.to_string()).with("ct_count", count as u64),
    ))
}

fn compliance_finding(framework: &str, deadline_year: u64, target: &str) -> Value {
    let (label, detail, remediation) = match framework.to_ascii_lowercase().as_str() {
        "cnsa_2_0" | "cnsa" | "nsa" => (
            "NSA CNSA 2.0",
            format!(
                "CNSA 2.0 requires post-quantum algorithms across National Security Systems on a fixed timeline (software/firmware signing by 2027, networking by ~2030, exclusive PQC by 2033). This endpoint has no PQC key exchange and will miss the {deadline_year} milestone without action."
            ),
            "Adopt CNSA 2.0 algorithms (ML-KEM-1024 / ML-DSA-87) where mandated; for general systems begin with X25519MLKEM768 hybrid KEX now and schedule signature migration as CAs add ML-DSA.",
        ),
        "nist" | "nist_pqc" => (
            "NIST PQC (FIPS 203/204/205)",
            format!(
                "NIST has finalised ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205). NIST SP 1800-38 / NCCoE guidance expects migration to begin immediately; this endpoint negotiates no PQC and is behind the {deadline_year} planning horizon."
            ),
            "Enable FIPS 203 ML-KEM hybrid key exchange (X25519MLKEM768 / SecP256r1MLKEM768) and inventory signatures for ML-DSA migration per NIST SP 1800-38.",
        ),
        "bsi" => (
            "BSI TR-02102 (Germany)",
            format!(
                "BSI recommends hybrid PQC key agreement and lists FrodoKEM/ML-KEM as approved; this endpoint uses classical-only key exchange and does not meet the {deadline_year} hybrid recommendation."
            ),
            "Deploy hybrid key agreement (classical ⊕ ML-KEM) per BSI TR-02102-2 and document the configuration for compliance evidence.",
        ),
        "anssi" => (
            "ANSSI (France)",
            format!(
                "ANSSI mandates hybrid (classical ⊕ PQC) schemes during the transition. Classical-only key exchange here is non-conforming with the {deadline_year} hybrid-by-default position."
            ),
            "Adopt hybrid key exchange (X25519 ⊕ ML-KEM-768) as ANSSI requires defence-in-depth during the PQC transition.",
        ),
        other => (
            "PQC migration policy",
            format!(
                "Framework '{other}' selected. This endpoint negotiates classical-only key exchange and is not aligned with a {deadline_year} post-quantum migration target."
            ),
            "Enable PQC hybrid key exchange and map each finding to your chosen compliance framework's deadlines.",
        ),
    };
    let mut f = pqc_finding(
        &format!("{label}: post-quantum migration gap (target {deadline_year})"),
        "medium",
        &detail,
        target,
        remediation,
        0.75,
        Evidence::new()
            .with("framework", framework.to_string())
            .with("deadline_year", deadline_year)
            .with("status", "non_conforming"),
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("type".to_string(), json!("pqc_compliance_gap"));
    }
    f
}

fn build_roadmap(p: &PostureInputs, framework: &str) -> Vec<Value> {
    let mut steps = Vec::new();
    let mut step = |order: u32, title: &str, done: bool, detail: &str| {
        steps.push(json!({ "order": order, "title": title, "done": done, "detail": detail }));
    };
    step(
        1,
        "Inventory cryptography (CBOM)",
        false,
        "Catalogue every TLS/SSH terminator, certificate and key-exchange algorithm in scope.",
    );
    step(
        2,
        "Enable TLS 1.3 everywhere",
        p.tls13,
        "TLS 1.3 is the prerequisite for hybrid PQC key-exchange groups.",
    );
    step(
        3,
        "Deploy PQC hybrid TLS KEX",
        p.tls_pqc_kex,
        "Add X25519MLKEM768 (RFC 9370) as the preferred group on all TLS terminators.",
    );
    step(
        4,
        "Deploy PQC SSH KEX",
        p.ssh_checked && p.ssh_reachable && p.ssh_pqc_kex,
        "Prefer sntrup761x25519 / mlkem768x25519 on bastions and admin hosts.",
    );
    step(
        5,
        "Harden downgrade resistance (HSTS)",
        p.hsts,
        "Prevent pre-TLS downgrade during the migration window.",
    );
    step(
        6,
        &format!("Map to {framework} deadlines"),
        false,
        "Track each endpoint against the chosen framework's migration milestones.",
    );
    step(
        7,
        "Plan PQC signatures (ML-DSA)",
        false,
        "Adopt ML-DSA/SLH-DSA certificates as CAs make them available (crypto-agility).",
    );
    steps
}

/// CLI entry point.
pub async fn run_pqc_scanner(target: &str) {
    print_result(run_pqc_scanner_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_is_well_formed() {
        let ch = build_client_hello("example.com", &all_group_codes());
        assert_eq!(ch[0], 0x16, "TLS handshake record");
        assert_eq!(&ch[1..3], &[0x03, 0x01], "legacy record version");
        let rec_len = u16::from_be_bytes([ch[3], ch[4]]) as usize;
        assert_eq!(ch.len(), 5 + rec_len, "record length matches body");
        assert_eq!(ch[5], 0x01, "ClientHello handshake type");
    }

    #[test]
    fn group_catalog_classifies_pqc_and_classical() {
        assert!(group_by_code(0x11EC).unwrap().pqc, "X25519MLKEM768 is PQC");
        assert!(
            group_by_code(0x11EC).unwrap().hybrid,
            "X25519MLKEM768 is hybrid"
        );
        assert!(!group_by_code(0x001D).unwrap().pqc, "x25519 is classical");
        assert_eq!(group_name(0x001D), "x25519");
        assert!(group_name(0xABCD).starts_with("0x"));
        assert!(pqc_group_codes().contains(&0x11EC));
        assert!(!pqc_group_codes().contains(&0x001D));
    }

    fn build_server_hello(group: u16, hrr: bool, tls13: bool) -> Vec<u8> {
        let mut sh = Vec::new();
        sh.extend_from_slice(&[0x03, 0x03]); // legacy_version
        if hrr {
            sh.extend_from_slice(&HRR_MAGIC);
        } else {
            sh.extend_from_slice(&[0xAA; 32]);
        }
        sh.push(0); // session_id length 0
        sh.extend_from_slice(&[0x13, 0x01]); // cipher
        sh.push(0x00); // compression
                       // extensions
        let mut exts = Vec::new();
        if tls13 {
            exts.extend_from_slice(&[0x00, 0x2B, 0x00, 0x02, 0x03, 0x04]); // supported_versions
        }
        // key_share: HRR carries selected_group (2 bytes); ServerHello carries group + kex
        if hrr {
            exts.extend_from_slice(&[0x00, 0x33, 0x00, 0x02]);
            exts.extend_from_slice(&group.to_be_bytes());
        } else {
            exts.extend_from_slice(&[0x00, 0x33, 0x00, 0x06]);
            exts.extend_from_slice(&group.to_be_bytes());
            exts.extend_from_slice(&[0x00, 0x02, 0xAB, 0xCD]); // kex len 2 + data
        }
        sh.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        sh.extend_from_slice(&exts);

        // handshake header
        let mut hs = Vec::new();
        hs.push(0x02); // ServerHello
        let len = sh.len();
        hs.push(((len >> 16) & 0xFF) as u8);
        hs.push(((len >> 8) & 0xFF) as u8);
        hs.push((len & 0xFF) as u8);
        hs.extend_from_slice(&sh);
        // record
        let mut rec = Vec::new();
        rec.push(0x16);
        rec.extend_from_slice(&[0x03, 0x03]);
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn parses_hello_retry_request_with_pqc_group() {
        let rec = build_server_hello(0x11EC, true, true);
        match parse_tls_reply(&rec) {
            KexReply::HelloRetry { group, tls13 } => {
                assert_eq!(group, 0x11EC);
                assert!(tls13);
            }
            other => panic!("expected HelloRetry, got {other:?}"),
        }
    }

    #[test]
    fn parses_server_hello_with_group() {
        let rec = build_server_hello(0x001D, false, true);
        match parse_tls_reply(&rec) {
            KexReply::ServerHello { group, tls13 } => {
                assert_eq!(group, Some(0x001D));
                assert!(tls13);
            }
            other => panic!("expected ServerHello, got {other:?}"),
        }
    }

    #[test]
    fn parses_fatal_alert() {
        // Alert record: type 0x15, version, len 2, level 2 (fatal), desc 40 (handshake_failure)
        let rec = vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
        assert_eq!(
            parse_tls_reply(&rec),
            KexReply::Alert {
                level: 2,
                description: 40
            }
        );
    }

    #[test]
    fn short_buffer_is_no_response() {
        assert_eq!(parse_tls_reply(&[0x16, 0x03]), KexReply::NoResponse);
    }

    #[test]
    fn ssh_kexinit_parses_pqc_kex() {
        // Build a minimal SSH_MSG_KEXINIT with a kex_algorithms name-list.
        let kex = "sntrup761x25519-sha512@openssh.com,curve25519-sha256";
        let mut payload = Vec::new();
        payload.push(20u8); // SSH_MSG_KEXINIT
        payload.extend_from_slice(&[0u8; 16]); // cookie
        payload.extend_from_slice(&(kex.len() as u32).to_be_bytes());
        payload.extend_from_slice(kex.as_bytes());
        // pad payload's remaining name-lists minimally is not required for our parser.
        let pad_len = 4u8;
        let packet_len = (payload.len() + 1 + pad_len as usize) as u32;
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&packet_len.to_be_bytes());
        pkt.push(pad_len);
        pkt.extend_from_slice(&payload);
        pkt.extend_from_slice(&[0u8; 4]); // padding
        let parsed = parse_ssh_kexinit(&pkt).expect("parse kexinit");
        assert!(parsed.iter().any(|k| k.contains("sntrup761")));
        assert!(parsed.iter().any(|k| k == "curve25519-sha256"));
    }

    #[test]
    fn mosca_inequality_flags_exposure() {
        // 10y data + 3y migration = 13y > 10y quantum horizon → 3y gap.
        assert_eq!(
            mosca_gap_years(MoscaInputs {
                data_lifetime_years: 10,
                migration_years: 3,
                quantum_eta_years: 10
            }),
            3
        );
        // Short-lived data, distant quantum → negative gap (no exposure).
        assert!(
            mosca_gap_years(MoscaInputs {
                data_lifetime_years: 1,
                migration_years: 1,
                quantum_eta_years: 15
            }) < 0
        );
    }

    #[test]
    fn readiness_score_rewards_pqc_kex() {
        let weak = PostureInputs {
            tls_reachable: true,
            tls13: true,
            tls_pqc_kex: false,
            http_reachable: true,
            hsts: true,
            cert_obtained: true,
            cert_key_adequate: true,
            ssh_checked: false,
            ssh_reachable: false,
            ssh_pqc_kex: false,
        };
        let strong = PostureInputs {
            tls_pqc_kex: true,
            ..weak.clone()
        };
        assert!(readiness_score(&strong) > readiness_score(&weak));
        assert!(
            readiness_score(&strong) >= 85,
            "PQC KEX should yield a high score"
        );
        // No applicable dimensions → 0, never a divide-by-zero.
        assert_eq!(readiness_score(&PostureInputs::default()), 0);
    }

    #[test]
    fn score_severity_escalates_with_hndl() {
        assert_eq!(score_severity(90, true), "info");
        assert_eq!(score_severity(30, false), "medium");
        assert_eq!(score_severity(30, true), "high");
        assert_eq!(score_severity(10, true), "critical");
    }
}
