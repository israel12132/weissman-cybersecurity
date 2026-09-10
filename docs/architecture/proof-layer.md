# Proof layer (P1)

Safe exploitability validation. Findings and campaign steps move
**observed → validated_safe_proof → proven** (or **failed_proof** /
**not_applicable**) using evidence that already exists plus bounded in-scope
differentials. Privilege, lateral, and impact WorldState facts unlock **only**
when `proof_status = proven`. Weissman never invents proof, never opens a
shell, and never runs destructive payloads.

P0 campaign fabric remains the planner + dispatch spine
(`docs/architecture/adversary-campaign-fabric.md`). This document is **P1
only**. P2 APT profiles are out of scope.

## Why it exists

Hardened customers still produce live findings. Isolated engine runs and job
success are not the same as exploitability. P1 raises confidence:

1. Classify engine output (IDOR/authz differentials, open-redirect canary, SQL
   error indicators, XSS canary reflection).
2. Correlate **this finding's** OAST tokens to `oast_interaction_hits` (never
   unrelated callbacks).
3. Confirm cloud/identity misconfig when the engine already attached read-only
   confirmation.
4. Optionally run **in-scope GET-only** web differentials (quote vs baseline
   SQL errors, XSS canary, auth-bypass headers, sibling numeric ID, open
   redirect to `pentest.weissman-redirect-probe.invalid`).
5. Feed **Proven** facts into campaign WorldState so STRIPS cannot mint
   foothold / privilege / impact from observation alone.

Live verify `CONFIRMED` upgrades a finding to `validated_safe_proof` only. It
does **not** unlock privilege facts. A succeeded campaign step plus validated
safe proof becomes `proven`.

## Status model

| Status | Meaning |
|--------|---------|
| `observed` | Finding or step exists; no confirmation-grade evidence |
| `validated_safe_proof` | Safe confirmation (live verify, weak differential) — not privilege unlock |
| `proven` | Evidence-backed exploitability. Sticky. Unlocks privilege facts |
| `failed_proof` | Safe adapters ran and did not confirm. Retry allowed. Not an auto-FP |
| `not_applicable` | Informational TLS/banner-style rows with no proof surface |

Transitions: `observed` → any; `validated_safe_proof` → `proven` or
`failed_proof`; `failed_proof` may retry to validated/proven; **proven does not
downgrade**.

Evidence is stored in `weissman_proof_artifacts` (RLS, tenant + client scoped):
request/response diffs, OAST hit ids, screenshot refs, cloud confirmations.
Campaign steps keep a `proof_evidence` JSONB summary (`adapter`, `reason`,
`artifact_ids`). World snapshots keep `proven_facts`.

## Domain adapters

Reuse, do not widen blast radius:

| Domain | Proof source |
|--------|----------------|
| Web/API | Engine differentials already on the finding; optional in-scope GET probes |
| OAST | Tokens extracted from **that** finding only → `oast_interaction_hits` |
| Cloud/identity | Read-only confirmation already present (`confirmed`, public bucket, wildcard IAM) |
| Informational | `not_applicable` — no invented SQLi/RCE |

Hard rails (enforced in `fingerprint_engine/src/proof_layer.rs`):

- Authorized tenant/client scope (`validate_scan_target_in_scope`)
- No shells / no `xp_cmdshell` / no `DROP DATABASE` / no outfile dumps
- FP: proven paths call `fp_feedback::record_tp`. Failed proofs **do not**
  `record_fp` — noisy signatures still flow through analyst FP labelling
- Novel findings stay in-product; no auto external disclosure

## Campaign gate

On each campaign tick, after job reconcile:

1. `gate_succeeded_steps` classifies related findings + OAST.
2. `validated_safe_proof` + succeeded step → `proven`.
3. Observed web techniques may queue a live GET adapter (`live_queued`);
   `TechniqueProven` / `proof_failed` events append to the P0 hash chain.
4. WorldState rebuild: `campaign_world_from_findings` **drops** privilege facts
   unless the finding or a proven step already carries them.
5. Planner input strips `verified` unless `proof_status = proven` so
   `facts_from_findings` cannot mint `access:foothold`.
6. Privilege goals (`access:*`, `data:db_read`, `exec:code`, `impact:objective`)
   complete only when the goal is in `proven_facts`.
7. Needed techniques with `failed_proof` block the campaign
   (`proof_gate_blocked`).

`TechniqueProven` is **not** job success. Event kind `technique_proven` (v1)
already existed on P0; P1 adds `proof_failed` on the same versioned bus.

GET `/api/campaigns/:id` includes:

```json
"proof": {
  "privilege_facts_require_proven": true,
  "statuses": ["observed", "validated_safe_proof", "proven", "failed_proof", "not_applicable"],
  "safety_rails_no_shells": true
}
```

Steps expose `proof_status` and `proof_evidence`. WorldState exposes
`proven_facts`.

## API

| Method | Path | RBAC |
|--------|------|------|
| `GET /api/findings?proof_status=proven` | Filter inbox | authenticated |
| `GET /api/findings/:id/proof` | Artifacts for a finding | authenticated |
| `POST /api/findings/:id/proof` | Classify + optional live adapters (default live if no body) | analyst+ |
| `POST /api/campaigns/:id/steps/:step_id/proof` | Operator retry for one step; returns campaign bundle | operator+ |

POST finding body: `{ "live": true }`. Timeout 45s. Responses always include
`"invented": false` and `"safety_rails_no_shells": true`. A failed adapter
returns `failed_proof` with empty artifacts — never a fabricated finding.

## Command Center

- Findings Command Center: Proof column, **Proven only** filter (`?proof=1`),
  drawer **Run safe proof** + artifact list.
- Adversary Campaign Fabric (`/campaigns`): P1 PROOF badge, proof gate copy,
  proven WorldState chips, step proof badges, **Prove step**, Proven-steps
  filter.

i18n: `en` + `he`, no `defaultValue`.

## Try locally

1. Postgres 16 + Redis 7 (see root `AGENTS.md`). P0 campaign tables must exist
   (PR #333 / branch `cursor/adversary-campaign-fabric-8e07` if not on `main`).
2. `.env`: `DATABASE_URL`, `WEISSMAN_JWT_SECRET` (≥48 chars), `REDIS_URL`,
   `WEISSMAN_ADMIN_EMAIL` / `WEISSMAN_ADMIN_PASSWORD`, `WEISSMAN_MIGRATE_URL`.
3. `cargo build -p fingerprint_engine` then `./target/debug/weissman-server`
   (migrations apply on startup).
4. `cd frontend && npm run dev` → http://localhost:5173/command-center/
5. `POST /api/login` then open Findings. Rows start as **Observed**. Open a
   finding with engine differentials, OAST tokens, or a cloud confirmation and
   click **Run safe proof**, or wait for persist-time classification.
6. Open `/command-center/campaigns`, start a campaign. Unproven privilege facts
   do **not** appear in WorldState. After a succeeded step is proven, chips
   marked **proven** unlock the next STRIPS effects. Failed proofs block rather
   than invent a substitute technique.

## Tests

```bash
cargo test -p fingerprint_engine --lib proof_layer
cargo test -p fingerprint_engine --lib adversary_campaign
cd frontend && npx vitest run \
  src/components/findings/ProofStatusBadge.test.jsx \
  src/components/findings/FindingSafeProof.test.jsx \
  src/components/ui/FindingDrawer.test.jsx \
  src/pages/AdversaryCampaignFabric.test.jsx \
  src/lib/findingsUrlState.test.js \
  src/i18n/localeParity.test.js
node scripts/verify_i18n_no_default_values.mjs
bash scripts/check-migration-sync.sh
```
