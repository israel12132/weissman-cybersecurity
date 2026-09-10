# Discovery Lab v1

Weissman Discovery Lab is an **authorized-tenant** pipeline for finding
**previously unknown** issues (not yet a public CVE) on customer assets, then
packaging a **private disclosure draft**. Novel findings stay inside Weissman.

It is **not** a new production engine ID. Catalog wiring stays at the current
production count (verify with `node scripts/verify_engine_wiring.mjs`). The lab
reuses `fuzz_core` mutation + anomaly scoring, the multi-provider LLM router
(fail-open), and `fp_feedback` confidence / auto-suppress.

## Private-first disclosure (founder rule)

- Candidates and packs are **tenant-private**. They are not copied into the
  ordinary findings inbox.
- Weissman **never** submits, emails, or otherwise transmits a pack to CERT,
  government, vendor, or any external body. There is no outbound disclosure
  integration.
- Export (Markdown / JSON / PDF) is a **local download** so a human can send
  the draft privately later, if leadership decides.
- Pack status `submitted` is an **internal hold** only (operator still must
  send the file themselves). The UI marks `ready → disclosed` after a human
  send; it does not call an external API.
- Access is **admin / CEO / superadmin** (`require_discovery_lab_steward`).
  Operators, analysts, and customer-portal identities cannot read novel-finding
  details. Command Center route `/discovery-lab` is `RequireRole min="admin"`.

## Candidate lifecycle

`candidate → validated → customer_remediation → disclosure_ready → disclosed`

- Analysts (stewards) may skip `validated → disclosure_ready`.
- `suppress` (FP) is allowed from candidate / validated / remediation /
  disclosure-ready. You cannot disclose from `candidate` or `suppressed`.
- Opening a pack from a validated+ candidate moves it to `disclosure_ready`.
- Manually marking the pack `disclosed` sets the candidate to `disclosed`.

Pack lifecycle: `draft → ready → disclosed` (also `withdrawn`;
`ready → submitted` remains an internal hold for API compatibility).

## Authorization / scope

- Steward RBAC (`require_discovery_lab_steward`) + tenant RLS
  (`app_current_tenant_id()` **and** `weissman_client_row_visible(client_id)`).
- Mutation middleware: `/api/discovery-lab*` requires **admin**.
- `client_id` is required. `security_hardening::validate_scan_target_in_scope`
  pins the host; the async job payload stores `validated_scope`.
- Empty approved domains → `403` `target_out_of_scope`.
- LLM hypotheses that point at **another host** are dropped.

## Data model

Migrations (identical in both trees):

- `fingerprint_engine/migrations/20260910120000_discovery_lab.sql`
- `crates/weissman-db/migrations/20260910120000_discovery_lab.sql`

Tables: `discovery_lab_runs`, `discovery_lab_candidates`,
`discovery_disclosure_packs`, `discovery_disclosure_events` (append-only;
`REVOKE UPDATE, DELETE`). IDs are TEXT (sqlx uuid feature is off in this crate).

## API

| Method | Path | Role |
|--------|------|------|
| GET/POST | `/api/discovery-lab/runs` | admin+ steward |
| GET | `/api/discovery-lab/runs/:id` | admin+ steward |
| GET | `/api/discovery-lab/candidates` | admin+ steward |
| GET/PATCH | `/api/discovery-lab/candidates/:id` | admin+ (`action`: validate / suppress / remediation / disclosure_ready) |
| POST | `/api/discovery-lab/candidates/:id/disclosure` | admin+ |
| GET/PATCH | `/api/discovery-lab/disclosures` / `:id` | admin+ (`status` or `action`: draft → ready → disclosed; `submitted` = internal hold) |
| GET | `/api/discovery-lab/disclosures/:id/events` | admin+ |
| GET | `/api/discovery-lab/disclosures/:id/export?format=markdown\|json|pdf` | admin+ (local download only) |

Worker kind: `discovery_lab` (`async_job_executor`).

Scoring: novelty 0–1 from KEV/CVE/EPSS vs catalogued `fuzz_core` payload class vs
LLM-novel; noisy timing/length is `fp_routed`. EPSS during persist is the **local**
`epss_intel` cache only.

Pack JSON includes `stays_inside_weissman: true`, `outbound_submit: false`,
`human_send_required: true`.

## Command Center

Route: `/command-center/discovery-lab` (nav: Operations, admin+). RTL-safe; en + he i18n.

## Try locally

1. Postgres + Redis. `.env`: `DATABASE_URL`, `WEISSMAN_JWT_SECRET` (≥48 chars),
   admin email/password, `WEISSMAN_MIGRATE_URL` so the new migration applies.
2. `cargo build -p fingerprint_engine` then `./target/debug/weissman-server`.
3. `cd frontend && npm run dev` → login as **admin/ceo/superadmin** → **Discovery Lab**.
4. Pick a client with **approved domains**. Start a lab run against that host only.
5. If probes see anomalies: Validate / Suppress → Open disclosure pack → export
   Markdown / JSON / PDF. Weissman does not send the pack. Mark privately disclosed
   after a human send.

Never scan arbitrary internet; empty approved domains → 403 `target_out_of_scope`.

## Tests

```
cargo test -p fingerprint_engine discovery_lab --lib
cargo test -p fingerprint_engine rbac --lib -- require_discovery_lab
cargo test -p fingerprint_engine rls_policy_contract --test rls_policy_contract -- --nocapture
cd frontend && npx vitest run src/pages/DiscoveryLab.test.jsx src/lib/appNav.test.js src/lib/clientScope.test.js
node scripts/weissman-ui-audit.mjs
node scripts/verify_i18n_no_default_values.mjs
node scripts/verify_engine_wiring.mjs
```
