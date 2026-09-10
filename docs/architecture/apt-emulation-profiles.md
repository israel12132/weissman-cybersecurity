# APT emulation profiles (P2)

Named adversary playbooks that drive **Campaign Fabric (P0)** through the
**Proof layer (P1)**. An operator picks a profile; Weissman plans a
multi-stage, MITRE-mapped campaign using only production engines, advances
WorldState only when `proof_status = proven`, records detection/control gaps
when a stage would succeed in theory but proof fails or a control blocks, and
surfaces the existing Fix-First / `remediation_verify` loop.

This document is **P2 only**. P0:
[`adversary-campaign-fabric.md`](./adversary-campaign-fabric.md). P1:
[`proof-layer.md`](./proof-layer.md).

## Why it exists

Hardened customers still have evidence. Isolated engine runs and the
`threat_emulation` User-Agent path probes are not a coordinated purple-team
campaign. P2 adds:

1. A **profile library** (data + code) of six TTP sets mapped honestly to
   engines that already exist in `engine_dispatch`.
2. **Planner bias** — preferred techniques get lower STRIPS cost; extras
   (password-spray, cloud IAM, supply-chain harvest, OT fingerprint) are
   **not** in the default P0 library.
3. **CEM-DAGO wave preview** seeded with the profile's preferred engines. Waves
   never enqueue. `engine_dispatch` remains the only probe executor.
4. **Detection-gap nodes** linked to the campaign when proof fails, a job
   fails, a WAF/MFA/EDR signal is measurable, or OT ROE blocks.
5. **Remediation hook** — GET campaign includes the live Fix-First program;
   `POST /api/campaigns/:id/remediate` queues `remediation_verify` for
   **FIXED** findings only. `remediation_verified` still fires only on
   `outcome.closed`.

## Profiles (honest map)

| Id | Goal | Production engines (dispatchable) | Explicitly not claimed |
|----|------|------------------------------------|------------------------|
| `ransomware-affiliate` | `impact:objective` | `password_spray`, `credential_stuffing`, `rce_exploit_engine`, `host_privilege_escalation`, `lateral_movement`, `kill_chain`, `cloud_data_exfil` | Encryption, wipe, `ransomware_emulation` (agent-required) |
| `cloud-credential-thief` | `cred:leaked` | `ssrf_advanced`, `password_spray`, `credential_stuffing`, `cloud_iam_escalation` | Live key theft, IAM mutation |
| `web-initial-access` | `access:foothold` | `rce_exploit_engine`, `sqli_advanced`, `bola_idor` | Unmapped 0-days, XSS-to-RCE |
| `insider-pathing` | `access:crown_jewel` | `credential_stuffing`, `bola_idor`, `password_spray`, `host_privilege_escalation`, `lateral_movement`, `kill_chain` | Insider implant / mailbox bypass |
| `supply-chain-adjacent` | `access:foothold` | `supply_chain`, then evidenced `rce_exploit_engine` / `credential_stuffing` | Registry poison, SolarWinds-style implant |
| `ot-curious` | `access:internal` | `scada_ics` (passive), then proven `lateral_movement` / `kill_chain` | `ot_sis_triton_attack`, SIS, process disruption |

Code: `fingerprint_engine/src/apt_emulation_profiles.rs`.

If the goal is unreachable from observed facts, a profile may dispatch a
**gather** extra whose STRIPS preconditions are already met (e.g. harvest
manifests). That does **not** mint a foothold. If gather exhausts without a
grounded path, the campaign **blocks**.

## Invariants (P0 + P1 unchanged)

- Tenant + client RLS (`weissman_client_row_visible`) + `execution_scope_pin`.
- Dispatch only via `engine_dispatch` / `scan_routing`.
- `pick_dispatchable_step` still requires `technique_preconditions_met_in`.
- Privilege / lateral / impact facts unlock only when `proof_status = proven`.
- Novel findings stay in-product. `disclose_externally: false`.
- No shells, no destructive payloads, no invented findings.

## Detection gaps

Table `weissman_campaign_detection_gaps` (RLS, tenant + client). Event kind
`detection_gap_recorded` on the P0 hash chain.

| `gap_kind` | When |
|------------|------|
| `proof_failed` | P1 `failed_proof` on a needed step |
| `job_failed` | Engine job failed |
| `control_blocked` | Measurable WAF/403/429 signal in the reason |
| `roe_blocked` | OT / industrial ROE refused the probe |

`control_surface` is `waf` / `edr` / `mfa` / `proof_gate` / `ot_roe` /
`unknown`. Unknown unless the signal is in the evidence — we do not invent
WAF/EDR/MFA efficacy.

## API

| Method | Path | RBAC |
|--------|------|------|
| `GET /api/campaigns/profiles` | Catalog | authenticated |
| `POST /api/campaigns` | `{ client_id, goal?, profile_id? }` | operator+ |
| `GET /api/campaigns/:id` | Bundle + `emulation`, `detection_gaps`, `remediation` | authenticated |
| `POST /api/campaigns/:id/remediate` | Queue `remediation_verify` for FIXED findings | operator+ |

Portal sessions stay pinned via `force_json_client_id`.

## Command Center

Route: `/campaigns`. Select an APT profile, create, start. The detail pane
shows profile ROE + honest coverage, stage progress (pending / in progress /
proven / blocked), Proof badges, detection gaps, and Fix-First.

Related: `/threat-emulation` (HTTP path probes, not the campaign planner),
`/remediation`, `/cem-dago`, `/council-queue`.

## Try locally

1. Postgres 16 + Redis 7 (see root `AGENTS.md`). P0 + P1 tables must exist
   (PRs #333 / #334 if not on `main`).
2. `.env`: `DATABASE_URL`, `WEISSMAN_JWT_SECRET` (≥48 chars), `REDIS_URL`,
   `WEISSMAN_ADMIN_EMAIL` / `WEISSMAN_ADMIN_PASSWORD`, `WEISSMAN_MIGRATE_URL`.
3. `cargo build -p fingerprint_engine` then `./target/debug/weissman-server`.
4. `cd frontend && npm run dev` → http://localhost:5173/command-center/campaigns
5. `POST /api/login` then `GET /api/campaigns/profiles`. Create a campaign with
   `profile_id: "web-initial-access"` for a client that has authorized domains.
6. Start it. If the client has no evidenced path, the campaign **blocks**
   instead of inventing TTPs. Prove a succeeded step; privilege facts still
   stay locked until `proof_status=proven`. Failed proofs appear under
   Detection gaps. Open Fix-First from the campaign pane.

## Tests

```bash
cargo test -p fingerprint_engine --lib apt_emulation
cargo test -p fingerprint_engine --lib adversary_campaign
cargo test -p fingerprint_engine --lib attack_chain_planner
cargo test -p fingerprint_engine --lib proof_layer
cd frontend && npx vitest run \
  src/pages/AdversaryCampaignFabric.test.jsx \
  src/i18n/localeParity.test.js
node scripts/verify_i18n_no_default_values.mjs
bash scripts/check-migration-sync.sh
```
