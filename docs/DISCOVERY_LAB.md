# Discovery Lab v1

Weissman Discovery Lab is an **authorized-tenant** pipeline for finding
**previously unknown** issues (not yet a public CVE) on customer assets, then
packaging a **responsible-disclosure** draft for national CERT / government
cyber contacts.

It is **not** a 581st production engine ID. Catalog wiring stays at **580**
engines. The lab reuses `fuzz_core` mutation + anomaly scoring, the multi-provider
LLM router (fail-open), and `fp_feedback` confidence / auto-suppress.

## Why a dedicated pipeline

Ordinary findings land in `vulnerabilities` and are correlated against KEV/EPSS
signatures. Novel/0-day-class candidates must not drown in that inbox, and they
need a stricter lifecycle before anyone talks to a CERT:

`candidate → validated → customer_remediation → disclosure_ready → disclosed`

- Analysts may skip `validated → disclosure_ready` (CERT in parallel with the
  customer fix).
- `suppress` (FP) is allowed from candidate / validated / remediation /
  disclosure-ready. You cannot disclose from `candidate` or `suppressed`.
- Opening a pack from a validated+ candidate moves it to `disclosure_ready`.
- Marking the pack `disclosed` sets the candidate to `disclosed`.

## Authorization / scope

- Operator RBAC (`require_operator`) + tenant RLS (`app_current_tenant_id()` **and**
  `weissman_client_row_visible(client_id)`).
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
| GET/POST | `/api/discovery-lab/runs` | operator |
| GET | `/api/discovery-lab/runs/:id` | operator |
| GET | `/api/discovery-lab/candidates` | operator |
| GET/PATCH | `/api/discovery-lab/candidates/:id` | operator (`action`: validate / suppress / remediation / disclosure_ready) |
| POST | `/api/discovery-lab/candidates/:id/disclosure` | operator |
| GET/PATCH | `/api/discovery-lab/disclosures` / `:id` | operator (`status` or `action`: draft → ready → submitted → disclosed) |
| GET | `/api/discovery-lab/disclosures/:id/events` | operator |
| GET | `/api/discovery-lab/disclosures/:id/export?format=markdown\|json|pdf` | operator |

Worker kind: `discovery_lab` (`async_job_executor`).

Scoring: novelty 0–1 from KEV/CVE/EPSS vs catalogued `fuzz_core` payload class vs
LLM-novel; noisy timing/length is `fp_routed`. EPSS during persist is the **local**
`epss_intel` cache only.

## Command Center

Route: `/command-center/discovery-lab` (nav: Operations). RTL-safe; en + he i18n.

## Try locally

1. Postgres + Redis. `.env`: `DATABASE_URL`, `WEISSMAN_JWT_SECRET` (≥48 chars),
   admin email/password, `WEISSMAN_MIGRATE_URL` so the new migration applies.
2. `cargo build -p fingerprint_engine` then `./target/debug/weissman-server`.
3. `cd frontend && npm run dev` → login → **Discovery Lab**.
4. Pick a client with **approved domains**. Start a lab run against that host only.
5. If probes see anomalies: Validate / Suppress → Open disclosure pack → export
   Markdown / JSON / PDF.

## Tests

```
cargo test -p fingerprint_engine discovery_lab --lib
cargo test -p fingerprint_engine rls_policy_contract --test rls_policy_contract -- --nocapture
cd frontend && npx vitest run src/pages/DiscoveryLab.test.jsx
node scripts/weissman-ui-audit.mjs
node scripts/verify_i18n_no_default_values.mjs
node scripts/verify_engine_wiring.mjs
```
