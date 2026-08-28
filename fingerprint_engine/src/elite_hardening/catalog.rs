//! Numbered 100-control catalog (Part 2 elite hardening spec).

#[derive(Debug, Clone, Copy)]
pub struct Control {
    pub id: u16,
    pub section: u8,
    pub title: &'static str,
}

impl Control {
    pub fn section_title(&self) -> &'static str {
        match self.section {
            1 => "Offensive Engine Fabric",
            2 => "Evasion, Stealth & Covert Channels",
            3 => "AI/LLM Attacks & Supply Chain",
            4 => "Endpoint Agent & WSS",
            5 => "UEBA Anomalies",
            6 => "SOAR & Active Deception",
            7 => "Dijkstra Risk Graph",
            8 => "FAIR Financial Blast-Radius",
            9 => "RAG & Supreme Council",
            10 => "Ask Weissman & RLS",
            _ => "Unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ControlStatus {
    pub enforced: bool,
    pub detail: &'static str,
}

impl ControlStatus {
    pub fn ok(detail: &'static str) -> Self {
        Self {
            enforced: true,
            detail,
        }
    }
    pub fn gap(detail: &'static str) -> Self {
        Self {
            enforced: false,
            detail,
        }
    }
}

macro_rules! c {
    ($id:expr, $sec:expr, $title:expr) => {
        Control {
            id: $id,
            section: $sec,
            title: $title,
        }
    };
}

pub const CONTROLS: &[Control] = &[
    c!(
        1,
        1,
        "Zero-stub: every PRODUCTION_ENGINE_ID has an execution path"
    ),
    c!(
        2,
        1,
        "Calibrate live-probe TCP/TLS I/O to protect middlebox state tables"
    ),
    c!(
        3,
        1,
        "OT/ICS semantic FSM abort for Modbus, DNP3, S7, IEC 61850"
    ),
    c!(4, 1, "Evidence doubt: dual-probe or confidence ≥ 0.95"),
    c!(
        5,
        1,
        "LLM semantic fuzzer understands target tech before first mutation"
    ),
    c!(6, 1, "Quiet AWS/Azure IAM (no anomalous CloudTrail bursts)"),
    c!(7, 1, "Stateful BOLA/GraphQL session tracking"),
    c!(8, 1, "MITRE ATT&CK v19.1 currency — 226 techniques"),
    c!(
        9,
        1,
        "Internet-exposed OSINT/ASM assets get immediate graph priority"
    ),
    c!(
        10,
        1,
        "Mobile static-token + exposed-endpoint scan in core set"
    ),
    c!(11, 2, "HTTPS beaconing with 15–30% jitter"),
    c!(12, 2, "TLS policy: Forward Secrecy, TLS 1.2+ only"),
    c!(13, 2, "Aggressive User-Agent and HTTP header randomization"),
    c!(14, 2, "Inner encryption on WSS agent telemetry"),
    c!(15, 2, "Scan load spread across source IPs"),
    c!(16, 2, "DNS cascade: DoH → DoT → internal UDP"),
    c!(17, 2, "Strip scanner fingerprints from active payloads"),
    c!(18, 2, "Adaptive tenant_scan_limit by asset class"),
    c!(19, 2, "Timeout rate >20% → pause 300s and rotate evasion"),
    c!(20, 2, "OAST callbacks on high-reputation domains"),
    c!(21, 3, "RAG poisoning: anomalous vector block in pgvector"),
    c!(22, 3, "Prompt injection: 50+ jailbreak techniques"),
    c!(
        23,
        3,
        "CI/CD poisoning monitors + SECURITY_AND_COMPLIANCE.md"
    ),
    c!(24, 3, "Dependency hijack / typosquatting in manifests"),
    c!(
        25,
        3,
        "Hardened jailbreak engine (current LLM-sec research)"
    ),
    c!(26, 3, "Unsigned CI artifacts blocked"),
    c!(27, 3, "Shadow AI discovery probes"),
    c!(28, 3, "Model-weight hash verification"),
    c!(29, 3, "Block secrets in prompts to external LLMs"),
    c!(30, 3, "Sandbox embeddings; scan vectors for hidden code"),
    c!(31, 4, "Full symbol stripping on production agent"),
    c!(32, 4, "Efficient JWT validation at WSS edge"),
    c!(33, 4, "Disconnected UEBA sampling in encrypted memory"),
    c!(
        34,
        4,
        "Block DLL injection / process hollowing into the agent"
    ),
    c!(35, 4, "Hard resource cap: ~1% CPU, 5% burst"),
    c!(36, 4, "Installer verifies binary checksum before exec"),
    c!(37, 4, "Agent log tamper → High"),
    c!(38, 4, "Least privilege (no root/SYSTEM unless required)"),
    c!(39, 4, "Reject unsigned agent updates"),
    c!(40, 4, "Survive local EDR disable attempts via watchdog"),
    c!(41, 5, "Z-score >3 medium, >6 high"),
    c!(42, 5, "Minimize sample I/O while keeping resolution"),
    c!(43, 5, "7-day learning before alerts"),
    c!(44, 5, "Hour-of-week hybrid cascade"),
    c!(45, 5, "First-seen process/port → medium"),
    c!(46, 5, "14-day sample retention purge"),
    c!(47, 5, "CPU/memory as cryptojack/ransomware precursor"),
    c!(48, 5, "Failed logins in host anomaly score"),
    c!(49, 5, "New unique user on core assets → alert"),
    c!(50, 5, "Cloud-safe standard deviation"),
    c!(51, 6, "Reliable off-transaction isolate_host"),
    c!(52, 6, "Playbook cooldown_seconds (anti-fatigue)"),
    c!(53, 6, "Bidirectional EDR containment connectors"),
    c!(54, 6, "Audit-log driven micro-segmentation isolate"),
    c!(55, 6, "SOAR honey-token deploy; touch → SEV-1"),
    c!(
        56,
        6,
        "Hack-Fix-Verify: auto-close only after successful absence re-scan of a proven-live host"
    ),
    c!(57, 6, "HMAC-SHA256 webhook dispatcher"),
    c!(58, 6, "Hierarchical incidents via finding clusters"),
    c!(
        59,
        6,
        "Active corroboration before isolating a business host"
    ),
    c!(60, 6, "Playbook run RCA on every failure"),
    c!(61, 7, "Live CVSS+exposure node weights"),
    c!(62, 7, "Edges only for real lateral + exploitable vulns"),
    c!(63, 7, "Recursive CTE / sub-second Dijkstra"),
    c!(64, 7, "CISA KEV maximum priority"),
    c!(65, 7, "Choke-point identification"),
    c!(66, 7, "attack_path_snapshots for trend"),
    c!(67, 7, "Auto internet-exposed entry tagging"),
    c!(68, 7, "Post-breach next-hop simulation"),
    c!(69, 7, "Graph memory discipline on the worker"),
    c!(70, 7, "Path speed enables pre-emptive block"),
    c!(71, 8, "SLE = asset_value × max(CVSS/10, 0.5)"),
    c!(72, 8, "ALE = SLE × min(EPSS×12, 12) × discount"),
    c!(73, 8, "KEV ARO floor 1.0"),
    c!(74, 8, "Dynamic asset-value rules (prod vs dev)"),
    c!(75, 8, "Financial snapshot history / ROI"),
    c!(76, 8, "Multi-currency onboarding"),
    c!(77, 8, "Per-tenant FAIR isolation (MSSP)"),
    c!(78, 8, "Cost-of-remediation vs risk reduction"),
    c!(79, 8, "Business-interruption cumulative damage"),
    c!(80, 8, "Transparent EPSS/KEV sources"),
    c!(81, 9, "HNSW index on supreme_council_memory"),
    c!(82, 9, "OpenAI-compatible embeddings"),
    c!(83, 9, "Persist winning pentest paths"),
    c!(84, 9, "Sandbox Supreme Council deliberation"),
    c!(85, 9, "ANN retrieval of similar strategies"),
    c!(86, 9, "Memory noise filter"),
    c!(87, 9, "Embedding refresh on model upgrade"),
    c!(88, 9, "Winning paths require confirmed findings"),
    c!(89, 9, "Memory-poisoning write ACL (DB trigger + definer)"),
    c!(90, 9, "Hybrid tabular + vector query performance"),
    c!(91, 10, "JSON QueryPlan only — never raw SQL from the LLM"),
    c!(92, 10, "13-table allow-list for weissman_ro"),
    c!(93, 10, "weissman_ro SELECT-only, statement_timeout 15s"),
    c!(94, 10, "RLS on 80+ multi-tenant tables"),
    c!(95, 10, "DDL keyword kill in QueryPlan compile"),
    c!(
        96,
        10,
        "Full nl_query_audit (async nlqa1 chain + JSON fallback)"
    ),
    c!(97, 10, "Hard LIMIT on every Ask query"),
    c!(98, 10, "GUC app.current_tenant_id session isolation"),
    c!(99, 10, "Parameterized SQL only"),
    c!(100, 10, "Fail-closed on validator/RLS/DB faults"),
];
