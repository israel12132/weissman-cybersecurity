# Adversary Campaign Fabric (P0)

Sync layer that turns isolated production engines into a coordinated,
evidence-grounded adversary campaign. **This document is P0.** Safe
exploitability validation that upgrades steps from observed → proven lives in
**[proof-layer.md](./proof-layer.md) (P1)**. P2 APT profiles are out of scope.

## Why it exists

Hardened customers still have evidence in `vulnerabilities`. Isolated engine
runs do not, by themselves, prove an attack path or drive the next authorized
probe. The fabric:

1. Seeds a STRIPS **WorldState** from live findings (`facts_from_findings`).
2. Plans with `attack_chain_planner::plan` (never invents capability).
3. Enqueues the next mapped production engine **inside authorized client scope**.
4. Rebuilds WorldState from new findings (FP-suppressed rows excluded).
5. Threads one tenant-scoped `campaign_id` across jobs, findings, SOAR, attack
   paths, CEM-DAGO blackboard, and the Command Center UI.

## Spine (reuse, not a fourth bus)

| Layer | Role |
|-------|------|
| `weissman_campaigns` + steps + world snapshots + audit | Domain model |
| `weissman_campaign_events` | Versioned append-only event chain (v1) |
| `weissman-job-bus` | Existing job envelope; payload carries `campaign_id` |
| CEM-DAGO blackboard `campaign:{uuid}` | Live Redis projection of WorldState |
| `engine_dispatch` | **Only** probe executor |
| Council HITL (`/council-queue`) | May propose allow-listed techniques; P0 never auto-fires them |

Event kinds (v1): `campaign_created`, `campaign_started`, `campaign_paused`,
`world_state_snapshot`, `finding_observed`, `path_snapshot_taken`,
`technique_planned`, `technique_dispatched`, `technique_proven`,
`technique_failed`, `goal_reached`, `campaign_blocked`,
`mesh_blackboard_seeded`, `remediation_verified`, `proof_failed` (P1).

This is **not** a fourth bus. Jobs stay on weissman-job-bus (payload
`campaign_id`). Redis/CEM-DAGO blackboard `campaign:{uuid}` is the live
projection. Postgres `weissman_campaign_events` is the durable hash chain.

`TechniqueProven` is **not** job success. P1 requires `proof_status = proven`
and attached safe evidence before privilege / lateral / impact facts enter
WorldState. Observation facts (`service:web`, `vuln:*`) still seed from live
findings.

`RemediationVerified` is emitted only when the existing `remediation_verify`
job reports `outcome.closed` (HFV `VERIFIED_FIXED`). Analyst `FIXED` does not
mint the event. Closed-loop verify is still the P0 bus stub; exploitability
proof is P1 (`docs/architecture/proof-layer.md`).

GET `/api/campaigns/:id` includes `spine`, `council`, and `mesh.waves`.
Waves are a **schedule preview**; they never enqueue. `engine_dispatch` is the
only probe executor. `pick_dispatchable_step` still requires
`technique_preconditions_met`.

Campaign-scoped Council HITL (`POST /api/council/hitl/propose` with
`campaign_id`) rejects technique-shaped ids that are not in
`allowlisted_techniques`. Narrative `chain_steps` are kept. Approve still
enqueues `council_debate` only (`safety_rails_no_shells: true`).

Spine columns (correlation only, never widen scope):
`attack_path_snapshots.campaign_id`, `council_hitl_queue.campaign_id`,
`weissman_playbook_runs.campaign_id`.

## Hard rails

- Tenant + client RLS (`weissman_client_row_visible`).
- `scan_routing` + `validate_scan_target_in_scope` + `execution_scope_pin`.
- Dispatch only when `technique_preconditions_met` on current WorldState.
- FP suppression (`fp_feedback::is_suppressed_by`) before fact seeding.
- Novel findings stay in-product; no auto external disclosure.
- Supreme Council proposals are filtered through `allowlisted_techniques`
  (library id + production engine). HITL remains on `CouncilHitlQueue`.
  Campaign-scoped propose rejects unauthorized technique-shaped ids; approve
  never auto-fires mapped engines.

## API

| Method | Path | RBAC |
|--------|------|------|
| `GET /api/campaigns` | List (optional `?client_id=`) | authenticated |
| `POST /api/campaigns` | Create draft | operator+ |
| `GET /api/campaigns/:id` | Bundle: campaign, WorldState, steps, events, mesh waves, spine, council | authenticated |
| `POST /api/campaigns/:id/start` | Plan + dispatch next evidenced step | operator+ |
| `POST /api/campaigns/:id/pause` | Stop further dispatches | operator+ |
| `GET /api/campaigns/:id/plan` | Plan + WorldState | authenticated |
| `GET /api/campaigns/:id/steps` | Step ledger | authenticated |
| `GET /api/campaigns/:id/events` | Event chain | authenticated |
| `POST /api/campaigns/:id/steps/:step_id/proof` | P1 safe-proof retry for one step | operator+ |

Portal sessions are pinned via `force_json_client_id` / `assigned_client_id`.

## Command Center

Route: `/campaigns` (`AdversaryCampaignFabric`). Nav: Operations → Adversary
Campaigns. Kill Chain (`/kill-chain`) links here. Related surfaces: Attack
Paths, Jobs, Council HITL, CEM-DAGO mesh.

## Try locally

1. Postgres 16 + Redis 7 (see root `AGENTS.md`).
2. `.env`: `DATABASE_URL`, `WEISSMAN_JWT_SECRET` (≥48 chars), `REDIS_URL`,
   `WEISSMAN_ADMIN_EMAIL` / `WEISSMAN_ADMIN_PASSWORD`.
3. Backend runs sqlx migrations on startup when `WEISSMAN_MIGRATE_URL` is set.
4. `cargo build -p fingerprint_engine` then `./target/debug/weissman-server`.
5. `cd frontend && npm run dev` → http://localhost:5173/command-center/campaigns
6. `POST /api/login` then create a campaign for a client that has authorized
   domains. Start it. WorldState and steps update from live engine jobs.

If the client has no findings that ground a path to the goal, the campaign
**blocks** (`goal_unreachable_from_observed_facts`) instead of inventing a chain.

## Tests

```bash
cargo test -p fingerprint_engine adversary_campaign attack_chain_planner scan_routing proof_layer --lib
cd frontend && npx vitest run src/pages/AdversaryCampaignFabric.test.jsx src/i18n/localeParity.test.js
node scripts/weissman-ui-audit.mjs
node scripts/verify_i18n_no_default_values.mjs
```

P1 proof how-to: `docs/architecture/proof-layer.md`.

## Technique → engine map

| Technique | Engine |
|-----------|--------|
| `exploit_rce_web` | `rce_exploit_engine` |
| `exploit_sqli_web` | `sqli_advanced` |
| `exploit_ssrf_metadata` | `ssrf_advanced` |
| `valid_accounts` | `credential_stuffing` |
| `abuse_authz` | `bola_idor` |
| `privilege_escalation` | `host_privilege_escalation` |
| `lateral_movement` | `lateral_movement` |
| `reach_crown_jewel` | `kill_chain` |
| `exfiltrate_db` | `database_exfil` |
| `exfiltrate_crown_jewel` | `cloud_data_exfil` |

All ids must pass `is_production_engine_id`. Effects are never assumed from a
successful job.
