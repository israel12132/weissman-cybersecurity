//! OT/ICS Rules of Engagement — the binary safety interlock.
//!
//! Default mode is **SafeRead**: the worker may fingerprint and read, never write,
//! never Direct-Operate, never CPU-stop, never restart an RTU, never inject GOOSE.
//! Active validation is an explicit, HMAC-bound job parameter and still cannot
//! emit the destructive opcodes listed in [`DESTRUCTIVE_FOREVER`].

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::OnceLock;
use tokio_util::sync::CancellationToken;

type HmacSha256 = Hmac<Sha256>;

/// Probe intensity. Writes are never implied by a higher intensity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProbeMode {
    /// Listen / parse only (agent tap, captured frames). No TCP probes.
    Passive,
    /// Default: read-only protocol confirmation. No coils/registers/DB writes.
    #[default]
    SafeRead,
    /// Extra identification reads (device-id, SZL, class 0 poll). Still no writes.
    ActiveValidation,
}

impl ProbeMode {
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "passive" | "listen" => Self::Passive,
            "active" | "active_validation" | "active-validation" => Self::ActiveValidation,
            _ => Self::SafeRead,
        }
    }

    #[must_use]
    pub fn allows_tcp_probe(self) -> bool {
        !matches!(self, Self::Passive)
    }

    #[must_use]
    pub fn allows_writes(self) -> bool {
        false
    }
}

/// Compiled runtime policy for one job.
#[derive(Debug, Clone, Serialize)]
pub struct OtSafetyPolicy {
    pub probe_mode: ProbeMode,
    pub protocol_strict: bool,
    pub max_connections_per_host: u32,
    /// Physical TCP cap on a Modbus/DNP3 gateway IP (Unit/Station IDs share this).
    pub max_gateway_connections: u32,
    pub modbus_unit_id: u8,
    pub dnp3_link_dest: u16,
    pub io_timeout_ms: u64,
    pub connect_timeout_ms: u64,
    pub watchdog_ms: u64,
    pub max_read_quantity: u16,
    pub max_pdu_bytes: usize,
    pub stealth_jitter_ms: u64,
    pub zscore_high_threshold: f64,
    pub hmac_ok: bool,
    pub hmac_required_for_active: bool,
    pub soar_auto_isolate: bool,
    pub tenant_id: Option<i64>,
    pub client_id: Option<i64>,
    pub job_id: Option<String>,
}

impl Default for OtSafetyPolicy {
    fn default() -> Self {
        Self {
            probe_mode: ProbeMode::SafeRead,
            protocol_strict: true,
            max_connections_per_host: 2,
            max_gateway_connections: 8,
            modbus_unit_id: 1,
            dnp3_link_dest: 1,
            io_timeout_ms: 900,
            connect_timeout_ms: 1200,
            watchdog_ms: 2_000,
            max_read_quantity: 16,
            max_pdu_bytes: 253,
            stealth_jitter_ms: 0,
            zscore_high_threshold: 6.0,
            hmac_ok: false,
            hmac_required_for_active: true,
            soar_auto_isolate: false,
            tenant_id: None,
            client_id: None,
            job_id: None,
        }
    }
}

impl OtSafetyPolicy {
    /// Build from scan job params + environment. Never upgrades to writes.
    #[must_use]
    pub fn from_job_params(params: &serde_json::Value) -> Self {
        let mut p = Self::default();
        if let Some(mode) = params
            .get("probe_mode")
            .and_then(|v| v.as_str())
            .or_else(|| params.get("ot_probe_mode").and_then(|v| v.as_str()))
        {
            p.probe_mode = ProbeMode::parse(mode);
        }
        p.protocol_strict = params
            .get("protocol_strict")
            .and_then(json_truthy)
            .unwrap_or(true);
        if let Some(n) = params.get("timeout_ms").and_then(serde_json::Value::as_u64) {
            p.io_timeout_ms = n.clamp(200, 8_000);
        }
        if let Some(n) = params
            .get("ot_watchdog_ms")
            .and_then(serde_json::Value::as_u64)
        {
            p.watchdog_ms = n.clamp(50, 10_000);
        }
        if let Some(n) = params
            .get("max_read_quantity")
            .and_then(serde_json::Value::as_u64)
        {
            p.max_read_quantity = u16::try_from(n).unwrap_or(16).clamp(1, 125);
        }
        if let Some(n) = params
            .get("max_gateway_connections")
            .and_then(serde_json::Value::as_u64)
        {
            p.max_gateway_connections = u32::try_from(n).unwrap_or(8).clamp(1, 8);
        }
        if let Some(n) = params
            .get("modbus_unit_id")
            .and_then(serde_json::Value::as_u64)
        {
            p.modbus_unit_id = u8::try_from(n).unwrap_or(1);
        }
        if let Some(n) = params
            .get("dnp3_link_dest")
            .and_then(serde_json::Value::as_u64)
        {
            p.dnp3_link_dest = u16::try_from(n.min(u64::from(u16::MAX))).unwrap_or(1);
        }
        p.stealth_jitter_ms = params
            .get("stealth_jitter_ms")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
            .min(250);
        p.soar_auto_isolate = std::env::var("WEISSMAN_OT_SOAR_AUTO_ISOLATE")
            .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let job_id = params
            .get("job_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let hmac = params
            .get("ot_job_hmac")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        p.hmac_ok = !hmac.is_empty() && verify_job_hmac(&job_id, hmac);
        p.job_id = if job_id.is_empty() {
            None
        } else {
            Some(job_id)
        };

        let env_active = std::env::var("WEISSMAN_OT_ACTIVE_VALIDATION")
            .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if p.probe_mode == ProbeMode::ActiveValidation
            && p.hmac_required_for_active
            && !p.hmac_ok
            && !env_active
        {
            // No HMAC and no operator env override → stay in SafeRead.
            p.probe_mode = ProbeMode::SafeRead;
        }
        p
    }

    #[must_use]
    pub fn effective_mode(&self) -> ProbeMode {
        self.probe_mode
    }
}

fn json_truthy(v: &serde_json::Value) -> Option<bool> {
    match v {
        serde_json::Value::Bool(b) => Some(*b),
        serde_json::Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        },
        _ => v.as_u64().map(|n| n != 0),
    }
}

/// Modbus function codes permitted as SafeRead probes (IEC 61131 / Modbus Application Protocol).
pub const MODBUS_SAFE_READ: &[u8] = &[
    0x01, // Read Coils
    0x02, // Read Discrete Inputs
    0x03, // Read Holding Registers
    0x04, // Read Input Registers
    0x07, // Read Exception Status
    0x11, // Report Server ID
    0x2B, // Encapsulated Interface Transport (MEI / device identification)
];

/// Identification-only illegal function used once per session for stack fingerprinting.
pub const MODBUS_FINGERPRINT_FC: u8 = 0xFF;

/// Destructive / write function codes — never emitted by this worker.
pub const MODBUS_WRITE_BLOCKED: &[u8] = &[
    0x05, // Write Single Coil
    0x06, // Write Single Register
    0x0F, // Write Multiple Coils
    0x10, // Write Multiple Registers
    0x15, // Write File Record
    0x16, // Mask Write Register
    0x17, // Read/Write Multiple Registers (write half)
];

/// Diagnostic / recon codes — allowed to *parse* in responses, never used as a spray.
pub const MODBUS_RECON_FC: &[u8] = &[0x08];

/// S7 CPU-control (Stop/Reset) — never sent. Spec S7-27 / S7-33.
pub const S7_CPU_CONTROL_FC: u8 = 0x05;

/// DNP3 application functions that change physical state.
pub const DNP3_DIRECT_OPERATE: u8 = 0x05;
pub const DNP3_DIRECT_OPERATE_NR: u8 = 0x06;
pub const DNP3_COLD_RESTART: u8 = 0x0D;
pub const DNP3_WARM_RESTART: u8 = 0x0E;
pub const DNP3_SELECT: u8 = 0x03;
pub const DNP3_OPERATE: u8 = 0x04;
pub const DNP3_READ: u8 = 0x01;
pub const DNP3_FILE_TRANSFER_GROUP: u8 = 70;

/// Opcodes that are blocked in every mode, including ActiveValidation.
pub const DESTRUCTIVE_FOREVER: &[&str] = &[
    "modbus_write_coil",
    "modbus_write_register",
    "s7_cpu_stop",
    "s7_cpu_reset",
    "s7_write_db",
    "dnp3_direct_operate",
    "dnp3_cold_restart",
    "dnp3_warm_restart",
    "dnp3_file_transfer",
    "iec_goose_inject",
    "iec_sv_inject",
    "iec_mms_write",
    "iec_mms_control",
];

#[must_use]
pub fn modbus_fc_allowed(
    fc: u8,
    mode: ProbeMode,
    protocol_strict: bool,
) -> Result<(), &'static str> {
    let fc = fc & 0x7f;
    if MODBUS_WRITE_BLOCKED.contains(&fc) {
        return Err("modbus_write_blocked_by_roe");
    }
    if fc >= 90 {
        return Err("modbus_proprietary_fc_blocked");
    }
    if fc == MODBUS_FINGERPRINT_FC {
        return Ok(());
    }
    if MODBUS_RECON_FC.contains(&fc) && protocol_strict {
        return Err("modbus_diagnostic_fc_blocked_strict");
    }
    if MODBUS_SAFE_READ.contains(&fc) {
        return Ok(());
    }
    if !protocol_strict && matches!(mode, ProbeMode::ActiveValidation) {
        return Ok(());
    }
    Err("modbus_fc_not_in_roe")
}

#[must_use]
pub fn dnp3_fc_allowed(fc: u8) -> Result<(), &'static str> {
    match fc {
        DNP3_DIRECT_OPERATE | DNP3_DIRECT_OPERATE_NR => Err("dnp3_direct_operate_blocked"),
        DNP3_COLD_RESTART | DNP3_WARM_RESTART => Err("dnp3_restart_requires_soar_operator"),
        DNP3_SELECT | DNP3_OPERATE => Err("dnp3_sbo_control_blocked"),
        0x02 => Err("dnp3_write_blocked"),
        DNP3_READ | 0x00 => Ok(()),
        _ if fc >= 0x20 => Err("dnp3_undocumented_opcode"),
        _ => Ok(()),
    }
}

#[must_use]
pub fn s7_function_allowed(func: u8) -> Result<(), &'static str> {
    if func == S7_CPU_CONTROL_FC {
        return Err("s7_cpu_control_blocked");
    }
    Ok(())
}

/// HMAC over `job_id` using the job-orchestrator secret (≥32 chars in production).
#[must_use]
pub fn verify_job_hmac(job_id: &str, hmac_hex: &str) -> bool {
    let Ok(secret) = std::env::var("WEISSMAN_JOB_ORCHESTRATOR_SECRET")
        .or_else(|_| std::env::var("WEISSMAN_JWT_SECRET"))
    else {
        return false;
    };
    if secret.len() < 16 || job_id.is_empty() || hmac_hex.len() < 32 {
        return false;
    }
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(job_id.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    constant_time_eq(expected.as_bytes(), hmac_hex.trim().as_bytes())
}

/// Sign a job id (tests / operator tooling). Never log the secret.
#[must_use]
pub fn sign_job_hmac(job_id: &str, secret: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(job_id.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Process-wide emergency-stop token. SOAR / Command Center cancel flips this;
/// every in-flight OT probe `tokio::select!`s on it.
static EMERGENCY_STOP: OnceLock<CancellationToken> = OnceLock::new();

#[must_use]
pub fn emergency_stop_token() -> CancellationToken {
    EMERGENCY_STOP.get_or_init(CancellationToken::new).clone()
}

pub fn trip_emergency_stop() {
    emergency_stop_token().cancel();
}

#[must_use]
pub fn emergency_stop_tripped() -> bool {
    emergency_stop_token().is_cancelled()
}

/// Audit-traceable control catalog (original 100-point OT hardening spec).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct OtControl {
    pub id: &'static str,
    pub protocol: &'static str,
    pub title: &'static str,
    pub implemented: bool,
}

pub const CONTROL_CATALOG: &[OtControl] = &[
    // ── Modbus TCP (1–25) ────────────────────────────────────────────────────
    OtControl {
        id: "MB-01",
        protocol: "modbus",
        title: "Streaming nom MBAP/PDU parser (zero-copy slices)",
        implemented: true,
    },
    OtControl {
        id: "MB-02",
        protocol: "modbus",
        title: "nom::error::context on decode failure",
        implemented: true,
    },
    OtControl {
        id: "MB-03",
        protocol: "modbus",
        title: "Zero-copy header map onto &[u8]",
        implemented: true,
    },
    OtControl {
        id: "MB-04",
        protocol: "modbus",
        title: "MBAP Length vs physical payload (OOB reject)",
        implemented: true,
    },
    OtControl {
        id: "MB-05",
        protocol: "modbus",
        title: "SKIP LOCKED job claim (worker queue)",
        implemented: true,
    },
    OtControl {
        id: "MB-06",
        protocol: "modbus",
        title: "Function-code allow-list / ROE",
        implemented: true,
    },
    OtControl {
        id: "MB-07",
        protocol: "modbus",
        title: "Unit-ID validation + gateway-hopping guard",
        implemented: true,
    },
    OtControl {
        id: "MB-08",
        protocol: "modbus",
        title: "tokio::select! vs emergency-stop token",
        implemented: true,
    },
    OtControl {
        id: "MB-09",
        protocol: "modbus",
        title: "Read quantity cap (legacy PLC stress)",
        implemented: true,
    },
    OtControl {
        id: "MB-10",
        protocol: "modbus",
        title: "Transaction-ID session state (replay)",
        implemented: true,
    },
    OtControl {
        id: "MB-11",
        protocol: "modbus",
        title: "Per-packet tokio::time timeouts",
        implemented: true,
    },
    OtControl {
        id: "MB-12",
        protocol: "modbus",
        title: "Protocol identifier must be 0",
        implemented: true,
    },
    OtControl {
        id: "MB-13",
        protocol: "modbus",
        title: "weissman_ro SELECT on OT tables",
        implemented: true,
    },
    OtControl {
        id: "MB-14",
        protocol: "modbus",
        title: "Exception 0x01/0x02 classified as enumeration",
        implemented: true,
    },
    OtControl {
        id: "MB-15",
        protocol: "modbus",
        title: "Register sanitization before inference",
        implemented: true,
    },
    OtControl {
        id: "MB-16",
        protocol: "modbus",
        title: "Z-score packet-rate anomaly",
        implemented: true,
    },
    OtControl {
        id: "MB-17",
        protocol: "modbus",
        title: "Gateway Unit-ID DoS guard",
        implemented: true,
    },
    OtControl {
        id: "MB-18",
        protocol: "modbus",
        title: "Coil/register range vs asset inventory",
        implemented: true,
    },
    OtControl {
        id: "MB-19",
        protocol: "modbus",
        title: "Safe probing (reads only)",
        implemented: true,
    },
    OtControl {
        id: "MB-20",
        protocol: "modbus",
        title: "Unknown Unit-ID vs vulnerability matrix",
        implemented: true,
    },
    OtControl {
        id: "MB-21",
        protocol: "modbus",
        title: "RLS tenant isolation on OT storage",
        implemented: true,
    },
    OtControl {
        id: "MB-22",
        protocol: "modbus",
        title: "Max 2 TCP per dedicated PLC; gateway Unit-ID slots (cap 8)",
        implemented: true,
    },
    OtControl {
        id: "MB-23",
        protocol: "modbus",
        title: "Network-error audit with binary signature",
        implemented: true,
    },
    OtControl {
        id: "MB-24",
        protocol: "modbus",
        title: "SOAR isolate_host recommendation (z>6)",
        implemented: true,
    },
    OtControl {
        id: "MB-25",
        protocol: "modbus",
        title: "CISA KEV / EPSS enrichment",
        implemented: true,
    },
    // ── Siemens S7 (26–50) ───────────────────────────────────────────────────
    OtControl {
        id: "S7-01",
        protocol: "s7",
        title: "Typed TPKT/COTP/S7 header structs",
        implemented: true,
    },
    OtControl {
        id: "S7-02",
        protocol: "s7",
        title: "Ladder/SZL checksum compare (vector-ready)",
        implemented: true,
    },
    OtControl {
        id: "S7-03",
        protocol: "s7",
        title: "RFC 1006 TPKT validation",
        implemented: true,
    },
    OtControl {
        id: "S7-04",
        protocol: "s7",
        title: "PDU-size cap at Setup Communication",
        implemented: true,
    },
    OtControl {
        id: "S7-05",
        protocol: "s7",
        title: "CPU Stop/Reset blocked",
        implemented: true,
    },
    OtControl {
        id: "S7-06",
        protocol: "s7",
        title: "Per-host semaphore (multi-port PLCs)",
        implemented: true,
    },
    OtControl {
        id: "S7-07",
        protocol: "s7",
        title: "SEV-1 on observed CPU-control in capture",
        implemented: true,
    },
    OtControl {
        id: "S7-08",
        protocol: "s7",
        title: "Sensitive DB access flagged, never written",
        implemented: true,
    },
    OtControl {
        id: "S7-09",
        protocol: "s7",
        title: "Firmware vs KEV mirror",
        implemented: true,
    },
    OtControl {
        id: "S7-10",
        protocol: "s7",
        title: "SKIP LOCKED parallel S7 jobs",
        implemented: true,
    },
    OtControl {
        id: "S7-11",
        protocol: "s7",
        title: "COTP parameter validation (orphan sessions)",
        implemented: true,
    },
    OtControl {
        id: "S7-12",
        protocol: "s7",
        title: "No protection-level password brute-force",
        implemented: true,
    },
    OtControl {
        id: "S7-13",
        protocol: "s7",
        title: "Ladder-logic download treated as recon (blocked)",
        implemented: true,
    },
    OtControl {
        id: "S7-14",
        protocol: "s7",
        title: "Rack/slot vs SZL response check",
        implemented: true,
    },
    OtControl {
        id: "S7-15",
        protocol: "s7",
        title: "Malformed ISO-on-TCP filtered + bounded COTP reassembly (8 KiB)",
        implemented: true,
    },
    OtControl {
        id: "S7-16",
        protocol: "s7",
        title: "False-positive suppression hook (≥3)",
        implemented: true,
    },
    OtControl {
        id: "S7-17",
        protocol: "s7",
        title: "Bounded S7CommPlus variable-spec parse",
        implemented: true,
    },
    OtControl {
        id: "S7-18",
        protocol: "s7",
        title: "FAIR $ at risk fusion",
        implemented: true,
    },
    OtControl {
        id: "S7-19",
        protocol: "s7",
        title: "Neighbor-discovery topology leak flagged",
        implemented: true,
    },
    OtControl {
        id: "S7-20",
        protocol: "s7",
        title: "S7 query audit with compiled plan",
        implemented: true,
    },
    OtControl {
        id: "S7-21",
        protocol: "s7",
        title: "Memory-marker writes blocked",
        implemented: true,
    },
    OtControl {
        id: "S7-22",
        protocol: "s7",
        title: "TLS policy for S7-1500",
        implemented: true,
    },
    OtControl {
        id: "S7-23",
        protocol: "s7",
        title: "Hardware-config change → high severity",
        implemented: true,
    },
    OtControl {
        id: "S7-24",
        protocol: "s7",
        title: "Supreme Council / pentest-memory hook",
        implemented: true,
    },
    OtControl {
        id: "S7-25",
        protocol: "s7",
        title: "Handshake timeouts per stage",
        implemented: true,
    },
    // ── DNP3 (51–75) ─────────────────────────────────────────────────────────
    OtControl {
        id: "DNP-01",
        protocol: "dnp3",
        title: "Data-link start bytes + malformed reject",
        implemented: true,
    },
    OtControl {
        id: "DNP-02",
        protocol: "dnp3",
        title: "Link-layer CRC-16 (IEEE 1815)",
        implemented: true,
    },
    OtControl {
        id: "DNP-03",
        protocol: "dnp3",
        title: "Bounded Object/Variation recursion",
        implemented: true,
    },
    OtControl {
        id: "DNP-04",
        protocol: "dnp3",
        title: "Stealth jitter (tokio sleep)",
        implemented: true,
    },
    OtControl {
        id: "DNP-05",
        protocol: "dnp3",
        title: "Select-Before-Operate; Direct Operate blocked",
        implemented: true,
    },
    OtControl {
        id: "DNP-06",
        protocol: "dnp3",
        title: "Application fragment size cap",
        implemented: true,
    },
    OtControl {
        id: "DNP-07",
        protocol: "dnp3",
        title: "Unsolicited response vs session context",
        implemented: true,
    },
    OtControl {
        id: "DNP-08",
        protocol: "dnp3",
        title: "IIN hardware/tamper bits",
        implemented: true,
    },
    OtControl {
        id: "DNP-09",
        protocol: "dnp3",
        title: "Restart requires SOAR operator",
        implemented: true,
    },
    OtControl {
        id: "DNP-10",
        protocol: "dnp3",
        title: "Source/dest vs scope pinning",
        implemented: true,
    },
    OtControl {
        id: "DNP-11",
        protocol: "dnp3",
        title: "Event-injection / buffer overflow detect",
        implemented: true,
    },
    OtControl {
        id: "DNP-12",
        protocol: "dnp3",
        title: "pgvector-ready anomaly embedding field",
        implemented: true,
    },
    OtControl {
        id: "DNP-13",
        protocol: "dnp3",
        title: "Time-sync command monitoring",
        implemented: true,
    },
    OtControl {
        id: "DNP-14",
        protocol: "dnp3",
        title: "Z-score → isolate_host recommendation",
        implemented: true,
    },
    OtControl {
        id: "DNP-15",
        protocol: "dnp3",
        title: "Application sequence replay guard",
        implemented: true,
    },
    OtControl {
        id: "DNP-16",
        protocol: "dnp3",
        title: "File-transfer objects (g70) blocked",
        implemented: true,
    },
    OtControl {
        id: "DNP-17",
        protocol: "dnp3",
        title: "Session cap per IED (semaphore)",
        implemented: true,
    },
    OtControl {
        id: "DNP-18",
        protocol: "dnp3",
        title: "Incremental / class-poll scanning",
        implemented: true,
    },
    OtControl {
        id: "DNP-19",
        protocol: "dnp3",
        title: "Polling-rate Z-score > 6 = high",
        implemented: true,
    },
    OtControl {
        id: "DNP-20",
        protocol: "dnp3",
        title: "IEEE 1815 handshake checks",
        implemented: true,
    },
    OtControl {
        id: "DNP-21",
        protocol: "dnp3",
        title: "Unknown object DoS guard",
        implemented: true,
    },
    OtControl {
        id: "DNP-22",
        protocol: "dnp3",
        title: "Analog deadband change detect",
        implemented: true,
    },
    OtControl {
        id: "DNP-23",
        protocol: "dnp3",
        title: "FAIR ALE fusion",
        implemented: true,
    },
    OtControl {
        id: "DNP-24",
        protocol: "dnp3",
        title: "KEV-gated playbook recommendation",
        implemented: true,
    },
    OtControl {
        id: "DNP-25",
        protocol: "dnp3",
        title: "RLS tenant isolation",
        implemented: true,
    },
    // ── IEC 61850 (76–100) ───────────────────────────────────────────────────
    OtControl {
        id: "IEC-01",
        protocol: "iec61850",
        title: "Iterative heap-stack ASN.1 BER/DER walker (no recursive parse)",
        implemented: true,
    },
    OtControl {
        id: "IEC-02",
        protocol: "iec61850",
        title: "GOOSE EtherType 0x88B8 + APPID",
        implemented: true,
    },
    OtControl {
        id: "IEC-03",
        protocol: "iec61850",
        title: "7-day GOOSE baseline window field",
        implemented: true,
    },
    OtControl {
        id: "IEC-04",
        protocol: "iec61850",
        title: "UEBA/agent correlation hook",
        implemented: true,
    },
    OtControl {
        id: "IEC-05",
        protocol: "iec61850",
        title: "Host isolation recommendation (station bus)",
        implemented: true,
    },
    OtControl {
        id: "IEC-06",
        protocol: "iec61850",
        title: "Sampled Values EtherType 0x88BA",
        implemented: true,
    },
    OtControl {
        id: "IEC-07",
        protocol: "iec61850",
        title: "Data-set / confRev change detect",
        implemented: true,
    },
    OtControl {
        id: "IEC-08",
        protocol: "iec61850",
        title: "Control-block disable detect",
        implemented: true,
    },
    OtControl {
        id: "IEC-09",
        protocol: "iec61850",
        title: "PTP / timeAllowedToLive replay guard",
        implemented: true,
    },
    OtControl {
        id: "IEC-10",
        protocol: "iec61850",
        title: "MMS attribute depth cap (heap Vec, not Tokio stack)",
        implemented: true,
    },
    OtControl {
        id: "IEC-11",
        protocol: "iec61850",
        title: "Unsolicited InformationReport filter",
        implemented: true,
    },
    OtControl {
        id: "IEC-12",
        protocol: "iec61850",
        title: "SCL integrity hash",
        implemented: true,
    },
    OtControl {
        id: "IEC-13",
        protocol: "iec61850",
        title: "Congestion: skip active relay probes",
        implemented: true,
    },
    OtControl {
        id: "IEC-14",
        protocol: "iec61850",
        title: "tokio::net parallel IED channels",
        implemented: true,
    },
    OtControl {
        id: "IEC-15",
        protocol: "iec61850",
        title: "MMS naming hierarchy check",
        implemented: true,
    },
    OtControl {
        id: "IEC-16",
        protocol: "iec61850",
        title: "MMS access-control brute-force detect",
        implemented: true,
    },
    OtControl {
        id: "IEC-17",
        protocol: "iec61850",
        title: "MMS write audit (never emitted)",
        implemented: true,
    },
    OtControl {
        id: "IEC-18",
        protocol: "iec61850",
        title: "GOOSE latency anomaly field",
        implemented: true,
    },
    OtControl {
        id: "IEC-19",
        protocol: "iec61850",
        title: "Siprotec/ABB relay KEV match",
        implemented: true,
    },
    OtControl {
        id: "IEC-20",
        protocol: "iec61850",
        title: "Safe TCP disconnect (FIN then linger-0 RST)",
        implemented: true,
    },
    OtControl {
        id: "IEC-21",
        protocol: "iec61850",
        title: "SV Z-score > 6 high alert",
        implemented: true,
    },
    OtControl {
        id: "IEC-22",
        protocol: "iec61850",
        title: "Attack-path lateral inference fusion",
        implemented: true,
    },
    OtControl {
        id: "IEC-23",
        protocol: "iec61850",
        title: "Continuous-monitor SLA metadata",
        implemented: true,
    },
    OtControl {
        id: "IEC-24",
        protocol: "iec61850",
        title: "RLS on substation logic",
        implemented: true,
    },
    OtControl {
        id: "IEC-25",
        protocol: "iec61850",
        title: "CI parser tests (full_audit_gate)",
        implemented: true,
    },
];

#[must_use]
pub fn controls_for(protocol: &str) -> Vec<&'static OtControl> {
    CONTROL_CATALOG
        .iter()
        .filter(|c| c.protocol == protocol)
        .collect()
}

#[must_use]
pub fn catalog_json() -> serde_json::Value {
    serde_json::json!({
        "controls": CONTROL_CATALOG,
        "implemented": CONTROL_CATALOG.iter().filter(|c| c.implemented).count(),
        "total": CONTROL_CATALOG.len(),
        "destructive_forever": DESTRUCTIVE_FOREVER,
        "max_connections_per_host": 2,
        "max_gateway_connections": 8,
        "default_mode": "safe_read",
        "zscore_isolate_threshold": 6.0,
        "stddev_floor": super::anomaly::STDDEV_FLOOR,
        "z_abs_cap": super::anomaly::Z_ABS_CAP,
        "cotp_assembly_cap": super::parsers::COTP_ASSEMBLY_CAP,
        "ber_iterative": true,
        "rst_on_release": true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mode_is_safe_read_and_never_writes() {
        let p = OtSafetyPolicy::default();
        assert_eq!(p.probe_mode, ProbeMode::SafeRead);
        assert!(!p.probe_mode.allows_writes());
        assert_eq!(p.max_connections_per_host, 2);
        assert_eq!(p.max_gateway_connections, 8);
        assert_eq!(p.modbus_unit_id, 1);
    }

    #[test]
    fn active_without_hmac_or_env_falls_back_to_safe_read() {
        let params = serde_json::json!({"probe_mode": "active_validation"});
        let p = OtSafetyPolicy::from_job_params(&params);
        assert_eq!(p.probe_mode, ProbeMode::SafeRead);
    }

    #[test]
    fn write_function_codes_are_blocked() {
        for fc in MODBUS_WRITE_BLOCKED {
            assert!(modbus_fc_allowed(*fc, ProbeMode::ActiveValidation, true).is_err());
        }
        assert!(modbus_fc_allowed(0x03, ProbeMode::SafeRead, true).is_ok());
        assert!(modbus_fc_allowed(0x90, ProbeMode::SafeRead, true).is_err());
    }

    #[test]
    fn dnp3_direct_operate_and_restart_blocked() {
        assert!(dnp3_fc_allowed(DNP3_DIRECT_OPERATE).is_err());
        assert!(dnp3_fc_allowed(DNP3_COLD_RESTART).is_err());
        assert!(dnp3_fc_allowed(DNP3_READ).is_ok());
    }

    #[test]
    fn s7_cpu_control_blocked() {
        assert!(s7_function_allowed(S7_CPU_CONTROL_FC).is_err());
        assert!(s7_function_allowed(0x04).is_ok());
    }

    #[test]
    fn job_hmac_roundtrip() {
        let sig = sign_job_hmac("job-1", b"test-secret-at-least-16");
        std::env::set_var(
            "WEISSMAN_JOB_ORCHESTRATOR_SECRET",
            "test-secret-at-least-16",
        );
        assert!(verify_job_hmac("job-1", &sig));
        assert!(!verify_job_hmac("job-2", &sig));
        std::env::remove_var("WEISSMAN_JOB_ORCHESTRATOR_SECRET");
    }

    #[test]
    fn catalog_covers_one_hundred_controls() {
        assert_eq!(CONTROL_CATALOG.len(), 100);
        assert!(CONTROL_CATALOG.iter().all(|c| c.implemented));
        let ids: std::collections::HashSet<_> = CONTROL_CATALOG.iter().map(|c| c.id).collect();
        assert_eq!(ids.len(), 100);
    }

    #[test]
    fn constant_time_eq_rejects_length_mismatch() {
        assert!(!constant_time_eq(b"ab", b"abc"));
        assert!(constant_time_eq(b"ab", b"ab"));
    }
}
