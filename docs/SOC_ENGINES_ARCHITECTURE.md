# Engine architecture

> Current as of 2026-06-09. See [`architecture.md`](architecture.md) for the
> system-wide picture.

**No mock data. No fake results.** Every engine is a live HTTP / TCP / DNS /
TLS / agent probe; an empty findings array is verified "0 findings", never
silently swallowed.

**Implementation language:** Rust, in the `fingerprint_engine` crate (built
into the `weissman-server` and `weissman-worker` binaries). Python files in
`src/` are legacy stubs preserved for archival reference; the runtime no
longer dispatches scans through them.

---

## 1. Engine registry

The authoritative list is in `backend/weissman-core/src/models/engine.rs`:

- `PRODUCTION_ENGINE_IDS` — **563 entries** (verify the live count with
  `node scripts/verify_engine_wiring.mjs`). Every ID maps to a real Rust
  function returning `EngineResult`. The orchestrator and the
  `/api/command-center/scan` endpoint will only dispatch IDs in this list
  (plus a small `EXTRA_SCAN_ENGINE_IDS` allow-list for legacy aliases).
- `DEFAULT_ORCHESTRATOR_ENGINES` — the subset auto-enabled per new tenant
  (~25 engines spanning OSINT / ASM / supply-chain / leak-hunting / TLS / etc).
- `is_production_engine_id(s)` / `resolve_engine_id(s)` — used everywhere that
  validates an engine ID against the registry.

### Engine groups

| Group | Files | Notable engines |
|-------|-------|----------------|
| Web | `advanced_web_engines.rs`, `bola_idor_engine.rs`, `fuzzer.rs` | XSS, SQLi, SSRF, IDOR/BOLA, GraphQL introspection, RFI, padding-oracle, cache poisoning |
| Cloud | `aws_attack_engine.rs`, `azure_attack_engine.rs`, `cloud_*`, `serverless_attack_engine.rs` | IAM enumeration, shadow-admin paths, serverless cold-path, K8s admission bypass |
| OT/ICS | `advanced_ot_engines.rs`, `ot_ics_engine.rs` | Modbus, DNP3, EtherNet/IP, IEC 61850, S7 (real protocol frames, not just port-scan) |
| AI / LLM | `advanced_ai_engines.rs`, `llm_*_engine.rs` | Jailbreak chains, prompt injection, model-inversion, RAG poisoning, plugin attack surface |
| Supply chain | `supply_chain_engine.rs`, `pipeline_engine.rs`, `cicd_*`, `container_registry_engine.rs`, `sbom_*` | SBOM diffing, leaked secrets across GitHub/GitLab, typosquatting, CI/CD poisoning |
| OSINT / ASM | `osint_engine.rs`, `asm_engine.rs`, `auto_domain_discovery_engine.rs`, `discovery_engine.rs` | Certificate Transparency, subdomain enum, tech fingerprinting |
| Stealth / evasion | `advanced_stealth_engines.rs`, `stealth_engine.rs` | Microsecond timing, header normalisation |
| Crypto | `advanced_crypto_engines.rs`, `crypto_engine.rs`, `pki_tls_engine.rs` | TLS posture, cert chain, PQC readiness |
| Fuzzers | `fuzzer.rs`, `semantic_fuzzer.rs`, `generative_fuzz_llm.rs`, `eternal_fuzz.rs`, `llm_*fuzz*` | HTTP-pool fuzzing, AST fuzzing, vLLM-assisted payloads |
| Mobile | `advanced_mobile_engines.rs` | MDM bypass, mobile SDK detection |
| Network | `advanced_network_engines.rs`, `network_*` | Network covert channels, MPLS VPN attack |
| Endpoint agent | `crates/weissman-agent/src/detections/*` | 15 on-host detections + UEBA baseline (see below) |

---

## 2. Dispatch path

```
Client request
   │  POST /api/command-center/scan { engine, target, client_id }
   ▼
weissman-server
   │  validates engine ∈ PRODUCTION_ENGINE_IDS
   │  validates target ∈ client.scope  (security_hardening::execution_scope_pin)
   │  enforces AI quota + tenant rate-limit + RBAC analyst+
   │  INSERT weissman_async_jobs (status='pending')
   │  returns 202 + job_id + status_url
   ▼
PostgreSQL queue (partial idx ix_async_jobs_pending(created_at, kind))
   ▼
weissman-worker (SKIP LOCKED, per-kind timeouts)
   │  picks job → calls engine_dispatch::run_engine(engine, target, ctx)
   ▼
engine_dispatch::run_engine
   │  match engine_id → call concrete Rust function
   │  engine returns EngineResult { status, message, findings: Vec<Value> }
   ▼
findings_persist::persist_engine_findings
   │  enriches with EPSS + KEV
   │  upserts vulnerabilities (stable finding_id, ON CONFLICT update)
   │  clusters via findings_correlator
   │  fires soar_playbook::dispatch_event (off-tx)
   ▼
Findings visible at /api/findings, /api/findings/clusters,
                    /api/dashboard/exec-kpis, /api/attack-paths/:id
```

`agent_required_*` engines are dispatched via the agent WebSocket instead of
running locally on the worker; see `endpoint_agents.rs` for the routing.

---

## 3. Endpoint agent

| Capability | File | Notes |
|-----------|------|-------|
| Process inventory / hollowing / DLL hijack | `process_hollowing.rs`, `process_modules.rs` | Walks `/proc/*/maps` etc. |
| Persistence mechanisms | `scheduled_tasks.rs` | systemd, launchd, cron, scheduled tasks |
| Bootkit / UEFI | `scheduled_tasks.rs` (`run_uefi`) | Compares to TPM measurements when available |
| ARP / DNS anomaly | `arp_table.rs` | Local LAN observations |
| Clipboard / screen-capture / insider exfil | `clipboard.rs` | macOS observers, Win32k hooks |
| Anti-debug / rootkit / forensics evasion | `process_modules.rs::run_unusual_runtime` | LD_PRELOAD detection, syscall anomalies |
| USB enumeration | `usb_devices.rs` | udev / IOKit / SetupAPI |
| EDR presence | `edr_presence.rs` | Defender, CrowdStrike, SentinelOne |
| Log tampering | `log_integrity.rs` | EventID 1102, journald gaps |
| **UEBA baseline sample** | `baseline.rs` | Ports + processes + users + load + memory + failed-logins + hour_of_week |

UEBA samples are POSTed to `/api/ueba/ingest`; the server runs the z-score +
categorical anomaly detector in `ueba_detector.rs` (see
[architecture.md](architecture.md#data-flow---endpoint-ueba-anomaly)).

---

## 4. Engine evidence guarantee

Every engine that emits a finding includes one of:

- a real HTTP response (status, headers, body excerpt),
- a real TCP banner,
- a real DNS / TLS handshake artifact,
- a real on-host observation (file path, process name, registry key),
- a real third-party intel hit (KEV match, EPSS score, GitHub Advisory).

`agent_required_ok` is returned (severity `info`) when an engine's signal can
only be observed on-host and no agent is currently online for the target —
the analyst gets a clear "deploy an agent" message rather than a false
negative.

---

## 5. Frontend orientation

- **Engine Matrix** (`/engines`) — all 563 engine IDs, status toggles, click-to-run.
- **Engine Detail** (`/engines/:engineId`) — per-engine docs, parameters,
  run-history table.
- **Findings Command Center** (`/findings`) — TanStack-Table view, drawer
  with EPSS/KEV badges, MITRE link, raw evidence JSON.
- **Cockpit** (`/`) — ExecKpiStrip + LiveActivityFeed + MitreCoverageHeatmap +
  SeverityTrendChart + TopMoversPanel (real-time, 15-30 s refresh).
- **PlaybookBuilder** (`/playbooks`) — visual SOAR editor.
- **AskWeissman** (`/ask`) — NL → safe-SQL chat.
- **AuditLog** (`/audit-log`) — paginated, filterable.

---

For day-to-day operations (env vars, migrations, intel workers, common ops
tasks, failure-mode reference) see [`operations.md`](operations.md).
