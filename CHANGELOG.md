# Changelog

All notable changes to the Weissman Cybersecurity platform are documented here.
Versions follow CalVer (`YYYY.MM.<patch>`); each entry maps to one rollout phase.

---

## [Unreleased]

### Added

- **Identity surface delta, dual-stack Host+SNI skip, ransomware preposition.**
  New live engines `identity_surface_delta` (OIDC/SAML on first-mover IdP hosts),
  `dualstack_edge_skip_fusion` (A vs AAAA with Host+SNI; finding only on status/WAF/body skip),
  and `ransomware_preposition_surface` (TCP of SMB/RDP/WinRM/Kerberos/LDAP/NFS — no encrypt).
  Teams alert delivery uses Adaptive Cards on `WEISSMAN_TEAMS_WEBHOOK_URL` and refuses Slack URLs.
  Attack Paths operators can PATCH crown-jewel / internet-exposed flags on the live risk graph.

- **Supreme Brain Part 6 — attack-path inference × FAIR blast radius × pentest RAG.**
  Dijkstra (BinaryHeap milli-cost) over live `risk_graph_nodes` / `risk_graph_edges`
  with CISA KEV / EPSS / CVSS / agent weights, what-if (block SMB/445), choke-points,
  and path ALE. FAIR snapshots gain concentration, delay cost, agent-protected ALE,
  and path-linked dollars. Pentest memory uses pgvector HNSW (`m=16`,
  `ef_construction=64`) with decay, checksums, and diversity sampling.
  New fusion engine `supreme_path_fair_rag`, APIs
  `GET /api/supreme-brain/:client_id`, `POST /api/attack-paths/:client_id/what-if`,
  `GET /api/pentest-memory/stats`, Command Center route `/supreme-brain`.

- **Dynamic compliance framework catalog.** `compliance_frameworks` is now the
  authoritative list of in-scope frameworks (migration
  `20260729120000_compliance_frameworks_dynamic_and_onboarding.sql`, mirrored to
  `weissman-db`). `GET /api/compliance/frameworks` reads from it and reports which
  source served the list via a `dynamic` flag, falling back to the historical list
  only when the table is unavailable. The hardcoded Rust vec is gone.
- **Six frameworks onboarded to the live control-mapping gate** — SOC2, NIS2, GDPR,
  IEC62443, PCI and CSA-CCM. Each canonical control is bound to a verified,
  audit-traceable, **evidence-only** platform source (Postgres RLS isolation,
  tamper-evident audit hash chain, distributed login lockout, startup-enforced TLS
  policy, agentless cloud posture, live vulnerability management). No engines were
  modified and no stale-engine references introduced. Previously these frameworks
  were listed in the UI but carried no live mappings, so they passed the enforcement
  gate un-evaluated.

### Changed

- **First `include!()` fragment converted to a real module (`cloud_posture_engine::runner`).**
  The 385K-LOC monolith glues code together with 51 `include!()` directives that fake module
  boundaries via shared scope, defeating cargo's per-module tooling. The safest leaf was
  converted honestly: `cloud_posture_engine/inc/runner.inc.rs` (a pure consumer defining only
  the 3 entry-point fns, referenced by nothing else) became `cloud_posture_engine/runner.rs`
  via `mod runner;` + `pub use` (preserving the 5 external call-site paths) + `use super::*`
  (re-importing the parent's `crate::` aliases and sibling-fragment types with zero visibility
  edits). Build + the 5 `cloud_posture_engine::tests` green. This removes one shared-scope
  `include!()` with the smallest possible blast radius; the domain sub-crate split and the
  remaining `.inc` conversions stay deferred (they need arsenal_config/engine_result/dispatch
  hoisted into a foundational crate first — multi-day, not build-safe incrementally).
- **Behavioral coverage for the SSE zero-trust stream-binding decision (`verify_stream_context`).**
  This pure function decides whether a hijacked/replayed SSE stream is terminated (403), yet its
  only sibling test asserted trivial path-string matching — the security decision beside it had
  ZERO coverage, so a refactor treating "no fingerprint supplied" as "skip the check" would have
  silently turned stream binding into a no-op and passed CI. Four tests now pin the three
  invariants: an IP-bound token rejects a different client IP; a fingerprint-bound token rejects
  a connection that presents NO fingerprint (the fail-closed case) or a wrong one; and a
  legacy/unbound token still passes. No product-code change — coverage that locks the contract.
- **Dev/CI build profile: fast, small, unoptimized — fat-LTO stays release-only.** The
  workspace had no `[profile.dev]`/`[profile.test]`, so unoptimized builds carried full
  `debug = 2` info and every integration-test binary statically linked the 385K-LOC
  `fingerprint_engine` with all of it — one such binary was ~2.7 GB, `target/debug/deps`
  reached ~19 GB, and CI/build disks filled. New explicit dev/test profiles set
  `codegen-units = 256` + `lto = false` (so an accidental inherit of the release fat-LTO
  can't creep into iterative builds), `debug = "line-tables-only"` for first-party code
  (panic/backtrace file:line still resolve), and `debug = false` for all third-party deps
  (`[profile.*.package."*"]`). Release keeps `lto = "fat"` / `codegen-units = 1` unchanged.
  Measured on a clean rebuild, no behaviour change, all unit tests green: the
  fingerprint_engine test binary dropped **2.7 GB → 325 MB**, `libaws_sdk_ec2.rlib`
  **1.2 GB → 553 MB**, and `target/debug/deps` **19 GB → 5.5 GB**. _Remaining Step 8
  work (own reviewed changes — larger blast radius, deployment-packaging paths this
  environment can't fully validate):_ splitting `fingerprint_engine` into domain
  sub-crates, converting the 46 `include!()` `.inc` fragments to real `mod` files,
  breaking the >4K-line god-files, and collapsing the byte-identical migration-tree
  duplication to a symlink/build-copy (the `check-migration-sync.sh` guard stays either
  way; trees currently verified in sync at 181 files).
- **One compliance integrity gate, not two.** The parallel mapping-integrity work is
  unified into the single `report_gate` + diagonal `Tm` watermark pipeline.
  `compliance_framework_orphans` folds three signals for every official artifact
  (framework PDF report **and** signed evidence pack):
  1. coverage gap (`find_orphaned_controls`),
  2. **listed-but-unmapped** — a framework the catalog lists but that carries no live
     control mapping now voids the artifact,
  3. **dead predicate** (`find_dead_predicate_controls`) — a control in
     `compliance_mappings` whose every row is structurally dead (no cloud rule id, no
     vulnerability predicate) can never be violated, so it is silently reported
     "compliant" forever.
- **Evidence pack is gated on the enabled compliance surface**, not a hardcoded slug
  list. `find_orphaned_controls` returns *no* orphans for a framework with zero live
  mappings (it cannot tell "not onboarded" from "fully covered"), so every framework in
  the old `COMPLIANCE_UI_SLUGS` list that carried no mappings — SOC2, NIS2, GDPR,
  IEC62443, PCI, CSA-CCM, plus NIST / HIPAA / FedRAMP — passed the gate untested. That
  hole is now closed from both sides: the six product frameworks are genuinely mapped,
  and the listed-but-unmapped signal fails any framework the catalog lists without
  mappings. NIST / HIPAA / FedRAMP are deliberately not listed until their evidence
  sources exist, so they are out of scope rather than silently "compliant".

### Fixed

- **The alert-pipeline meta-alerts are now proven to FIRE, not just present.** The promtool
  unit tests covered only the job-pipeline alerts; the two meta-alerts whose entire job is to
  detect a broken notification path — `AlertDeliveryFailing`
  (`rate(alertmanager_notifications_failed_total[10m]) > 0`) and `AlertingPipelineUnverified`
  (`up{job="alertmanager"} == 0`) — had NO firing test. `go_live_check.sh` only greps that the
  rules are present, and a present-but-unrunnable rule "reads as coverage" — the exact failure
  mode (a rule that fires but is never delivered) behind the documented multi-day silent
  outage. Added promtool cases proving each meta-alert fires on a threshold breach (climbing
  failure counter; Alertmanager unscrapeable) past its `for:` window AND stays silent when the
  pipeline is healthy (flat counter; `up == 1`), with the rendered operator-facing
  summary/description asserted. Verified: `promtool test rules` SUCCESS, `promtool check rules`
  SUCCESS on all rule files. _Deferred (needs a live Prometheus/Alertmanager):_ end-to-end
  delivery of a real notification to a real receiver.
- **Ask Weissman planner prompt is generated from the query SCHEMA (no more drift).**
  The NL→Plan LLM system prompt hand-listed the tables/columns it may target, and had
  silently fallen **4 tables behind** the real `nl_query::SCHEMA` allow-list — the
  `ot_ics_*` tables (OT/ICS fingerprints, safety events, protocol baselines, asset
  ranges) were queryable by `compile_plan` and granted to `weissman_ro`, but the planner
  was never told they existed, so an analyst could not reach them through Ask Weissman.
  The prompt's table enum and per-table column schema are now generated from `SCHEMA`
  itself (sorted, deterministic), so the LLM is always told about exactly the tables the
  compiler will accept — no more, no less. A new unit test
  (`planner_prompt_lists_every_schema_table`) locks the parity: every SCHEMA table must
  appear as both a schema line and an enum entry, and the enum count must equal
  `SCHEMA.len()`. _Deferred (needs CI-pipeline + live-stack validation not available
  here):_ retiring the deprecated `legacy/` Python layer, porting
  `tests/e2e/test_scan_pipeline_live.py` to Rust/Node, and removing the `python-audit`
  gate + live pytest contract from `ci.yml` — that touches a required CI job and a live
  E2E stack, so it belongs in its own reviewed change rather than a blind edit.
- **Actor engine descriptions no longer claim malware/C2/phishing the engine never runs.**
  The Command Center engine registry described the 20 threat-actor engines
  (`apt28_techniques` … `unc3944_ttps`) as "technique **simulation**" of specific malware
  and offensive TTPs — "X-Agent malware indicators", "credential harvesting via
  Responder/Mimikatz", "Sofacy C2 communication patterns", "DNC-style attack simulation",
  "AppleJeus cryptocurrency theft", "WannaCry ransomware genetic marker detection", etc.
  The actual engine (`advanced_apt_engines.rs::actor_exposure_scan`, made honest at the
  source in Step 7) does **none** of that: it maps the target's internet-facing attack
  surface to the software each actor is publicly documented (CISA/Mandiant) to exploit for
  initial access, and reports only on a live HTTP/TCP response with the relevant CVE/KEV —
  a remote unauthenticated scanner cannot "become" APT41. All 20 descriptions are rewritten
  to state exactly that (external, evidence-based initial-access exposure mapping — not
  malware, C2, or phishing emulation), so the UI stops advertising capabilities that don't
  exist. Registry structure unchanged (engine-wiring audit green; backend carried none of
  these claims). This is the honest actor-attributed-exposure repositioning from Step 17.
  _Remaining Step 17 work (own reviewed change):_ the per-tenant exportable, DB-enforced
  isolation attestation report built on the Step-1 live RLS introspection.
- **Finding provenance is honest: "has a sealed PoC" is no longer reported as "verified."**
  The findings read path emitted `"verified": poc_sealed`, conflating two very different
  assurance levels: `poc_sealed` means a tamper-evident PoC commitment was **sealed at
  scan time** (proves evidence was captured), while an **independent live re-scan that
  re-observed the finding** (`finding_live_verify`'s `reproducible`) is what proves it is
  still exploitable *now*. The payload now carries both signals distinctly — `has_poc`
  (sealed PoC commitment) and `reproduced` (live re-scan re-observed the finding) — so an
  auditor can tell "we kept proof" from "we reproduced it." The findings report
  (`ReportView`) surfaces the tiers honestly: the "How" column shows **reproduced (live)**
  vs **crypto_seal (PoC)**, and the verification breakdown counts a `reproduced_live`
  bucket separately instead of folding live-reproduced and merely-PoC-sealed findings into
  one "verified" number. (`verified`/`poc_sealed` are unchanged for backward compatibility;
  the new fields carry the honest distinction.) _Remaining Step 16 work (own reviewed
  change):_ the full structured replayable evidence object (request/response transcript +
  timing) with one-click reproduce, and the signed per-finding provenance ledger +
  `engine_reality` call-graph as an auditor-verifiable attestation.
- **Findings never show a fabricated CVSS; probe-sharing is disclosed at the source.**
  Two honesty gaps in how findings were scored and attributed:
  1. **CVSS display honesty.** Both the write path (`findings_persist.rs`) and the read
     path (`server_handlers_sqlx.inc`) derived the *displayed* `cvss_score` from severity
     when the engine published none (`severity_to_score`, so a `critical` with no measured
     CVSS rendered as a hard "9.5", and a null score rendered as "0"). To an auditor a
     fabricated number reads as a standards-based score the engine never measured, and it
     skews triage. The emitted `cvss_score` is now `null` (UI "—") whenever no real CVSS
     was published, mirroring the existing EPSS behaviour, via a single tested
     `cvss_for_display()` helper; severity still drives the internal risk ranking
     (`base_risk`/`effective_risk`) exactly as before — only the *displayed* value changed.
     New unit tests assert absent/zero CVSS serialises to JSON `null`, never `0.0`, and that
     a real published score is preserved and clamped.
  2. **Shared-probe disclosure.** The per-actor APT engines (`apt28_techniques`, …, 21 IDs)
     are one `actor_exposure_scan` probe parameterized by an `ActorProfile` (the edge
     products each actor is publicly documented by CISA/Mandiant to exploit, its IOCs, and
     the attributed actor name); the AI/LLM catalog IDs likewise group onto a handful of
     OWASP-LLM probes. Both module headers now state this plainly and point to
     `scripts/engine_reality_audit.mjs` as the authoritative count of distinct probe
     *behaviours* (329 real live probes), so the 595 catalog-ID figure is never read as 595
     distinct techniques. The contradicted `advanced_ai_engines.rs` comment ("no two share
     one behaviour") was corrected. **Attribution verified end-to-end:** findings persist
     with `source` = the *requested* engine ID (the one the operator launched), not the
     shared probe's internal name, and alias engines additionally stamp
     `alias_engine_id`/`canonical_engine_id`/`probe_fidelity` into `raw_data` — so a user
     always sees the engine they ran. No behavioural or count change was needed here; the
     gap was disclosure, now closed.
- **Scan-quota enforcement is now atomic (no TOCTOU revenue leak) + handler-honesty
  ratchet re-armed.** `gate_scan_enqueue_n` (billing) was a check-then-increment race:
  `enforce_scan_quota` read `scans_started`, then `record_scans_started` incremented it
  as a separate statement, so two concurrent enqueues both read the same value, both
  passed, and both incremented — overshooting the monthly cap (strict billing is on by
  default in production). It now increments and checks in ONE transaction via
  `INSERT … ON CONFLICT DO UPDATE … RETURNING scans_started`, so concurrent enqueues
  serialize on the `(tenant_id, period_ym)` row and an over-cap caller rolls its own
  increment back. Proven against a live Postgres: 30 concurrent atomic increments land
  exactly 30 (no lost updates). Separately, the `verify_handler_honesty.mjs` ratchet
  baseline was stale at **263** while the real count is **49** — 214 slots of silent
  regression room — so it is re-snapshotted to 49; any new store-down dishonesty now
  fails the build. _Deferred (tracked):_ burning the remaining 49 down (propagate DB
  failures as 503 + a generic client message instead of leaking `e.to_string()`), which
  is concentrated in `server_handlers_platform.inc` and `server_handlers_rest4.inc`.
- **Automated backups on the recommended docker-compose path + honest HA scoping.**
  The recommended compose stack ran ONE Postgres with no automated backups — a disk
  failure or a bad boot-time auto-migration was unrecoverable, while marketing a
  99.95% SLA. New `db-backup` service (`deploy/db-backup.sh`, wired into
  `docker-compose.prod.yml`) takes a nightly `pg_dump` (custom format) into the
  `weissman_db_backups` volume, verifies each archive is readable, and prunes to
  `WEISSMAN_BACKUP_RETENTION`. `deploy/PRODUCTION.txt` now states plainly that the
  compose path is single-node / non-HA and NOT for the SLA (pointing SLA-bound
  customers at the k8s/CNPG PITR stack), and its recommended command is aligned with
  the launcher and README to include `-f docker-compose.prod.yml` (so the hardening
  and the backup service actually apply). Backup script validated end-to-end
  (dump → archive-integrity check → retention) against a live Postgres 16 + pgvector.
- **Repaired the RED engine-count / metric source-of-truth gate and reconciled every
  headline number.** `node scripts/sync_doc_metrics.mjs --check` was failing on the
  committed tree (stale `docs/METRICS.md`) and the engine count was stated three
  different ways in `README.md` alone (594, 592, 563) — a "CI-verified numbers" claim
  that its own CI gate was red on. Regenerated `docs/METRICS.md` and
  `shared/engine_catalog.snapshot.json` from source, and reconciled every headline
  engine/migration figure to the single computed value (**595** production engine IDs =
  329 real live probes + 3 advisory-only + 204 aliases + 59 agent-required; 321 distinct
  impls; 180 migrations) across `README.md`, `AGENTS.md`, `docs/architecture.md`,
  `docs/SOC_ENGINES_ARCHITECTURE.md`, `SECURITY_AND_COMPLIANCE.md`, the two inspection
  runbooks, `SIG_CAIQ_PREP_QA.md`, `SYSTEM_TESTING_CHECKLIST.md` and
  `docs/sales/HOW-TO-PRESENT-he.md`. Hardened the guards so it cannot silently recur:
  `scripts/verify_doc_metrics.mjs` now asserts **every** occurrence of a gated metric
  (not just the first — the exact hole that let the second "592" through), covers the
  diagram/`entries` spots in `architecture.md` / `SOC_ENGINES_ARCHITECTURE.md`, and gates
  the advisory-only count; and CI now fails on any content drift of
  `engine_catalog.snapshot.json` (ignoring only its `generated_at` timestamp). _Deferred:_
  the `Weissman_Cybersecurity_Executive_Technical_Briefing` .md/.pdf pair (EN + HE) still
  carries a much older count (563 / 303 / 212 / 48) and needs a dedicated reconciliation +
  PDF regeneration.
- **SOAR playbook E2E verifier is hermetic.** `scripts/verify_soar_playbook_e2e.mjs`
  fired against a hard-coded `tenant_id: 1` / `client_id: 1`, violating the
  `soar_action_executions.client_id → clients(id)` foreign key on any stack where
  that row was never seeded. It now takes the tenant from the login response and
  seeds its own probe client, mirroring the fix already applied to the Rust
  `soar_playbook_e2e` integration test.
- **i18n `defaultValue` ratchet re-armed at zero.** The last two inline fallbacks
  (`common.clear` in `pages/RemediationHub.jsx`) are keyed in `en`/`he`, and
  `scripts/i18n-defaultvalue-baseline.json` — still pinned at the historical 223
  occurrences long after the migration finished, so it silently permitted a full
  regression — is tightened to `{}`. Any new inline `defaultValue` now fails the
  build. Closes item 1 of `docs/PRODUCT_DEBT_BACKLOG.md`.

### Security

- **Exportable per-tenant DB-enforced isolation attestation (`isolation_attestation`).** The
  Step-1 RLS/client-scope introspection was real but trapped inside pass/fail test bodies, so
  the DB truth that would BE an attestation was computed and thrown away — nothing could
  export it for a regulated buyer. New reusable emitter
  `build_isolation_attestation(pool) -> TenantIsolationAttestation` runs the same `pg_catalog`
  queries the contract test proves correct and returns the structured, serde-serializable live
  posture: per-table RLS enable/force/tenant-GUC-policy/`USING(true)` facts, per-table
  customer-visibility coverage, the active tenant ids (`active_tenant_ids()`), the
  tenant-GUC-role default guard, and a single `compliant` verdict. Compliance logic is pure and
  unit-tested (3 tests); the full emitter is covered by a live-Postgres test
  (`isolation_attestation_live`). Verified against the live migrated schema: **148 tenant
  tables + 88 client tables all compliant, 4 active tenants, compliant=true**. The scope is
  tenant/client ISOLATION posture (all connection-independent introspection), so the attestation
  is correct regardless of which pool builds it. _Deferred (its own change):_ the per-tenant
  HTTP export endpoint + PDF packaging, a signature/hash-chain over the exported report, and
  unifying the contract tests to consume this emitter as the single source of truth.
- **Structured, tamper-evident, hash-chained per-finding evidence (`finding_evidence_ledger`).**
  Live verification did real request/response I/O but collapsed it into a free-text `detail`
  string — so a CONFIRMED verdict could not be shown to an auditor as the transcript that
  justified it, and nothing bound that evidence into a tamper-evident chain. New module adds
  `EvidenceTranscript` (request method/URL/**header names only** — never values, which carry
  auth tokens — + body hash/len; response status/safe-header-subset/bounded snippet/body
  hash/len; timing `started_at`+`elapsed_ms`; `verifier_version`), a deterministic
  `canonical_bytes()` (fixed field order, sorted headers, record separators), a `commitment()`
  SHA-256 over it, and `sign(prev_hash, finding_id)` fusing the two existing provenance
  primitives — the `finding_attestation` HMAC receipt and the `nl_audit_*` prev-hash chain —
  into one hash-chained `LedgerEntry` (`entry_hash = SHA256(version|prev_hash|commitment|finding_id)`
  + HMAC receipt), with `verify_entry()` recomputing the commitment, chain link, and (when
  present) constant-time-verifying the receipt. Any mutation of the transcript, chain link, or
  finding id fails verification. Pure logic, 6 unit tests green (determinism, order-independence,
  tamper detection, chain linkage, forgery rejection). This is the replayable-evidence + signed
  ledger foundation of Step 16; wiring `finding_live_verify` to emit it, and one-click replay
  against a live target, follow in their own change.
- **CI supply-chain hardening is now self-enforcing locally, not just asserted on the runner.**
  The real controls (gitleaks, Trivy fs/config/image, Semgrep `--error`, CodeQL, cosign
  keyless signing + SLSA provenance + SBOM attestation, an anchored fail-closed
  `cosign verify` before `kubectl apply`, 40-hex-SHA-pinned actions, least-privilege
  `contents: read` token) live entirely in GitHub Actions YAML — so nothing local caught a
  silent weakening (dropping the gitleaks step, flipping a Trivy/Semgrep gate to advisory,
  unpinning an action back to a mutable tag, de-anchoring or removing the `cosign verify`).
  `full_audit_gate.sh` (G1–G7) never inspected `.github/workflows/`. New dependency-free
  `scripts/ci_supply_chain_gate.mjs` closes that hole: it (a) parses the workflow YAML and
  **asserts every fail-closed invariant is present and blocking**, and (b) runs a built-in
  secret scanner + k8s IaC linter over the deploy surface. A `--selftest` mode plants a
  secret + a privileged/insecure manifest into a temp fixture and asserts the detectors
  **fire** — proving the detection is real, not a stub — before any clean run is trusted.
  Wired into `full_audit_gate.sh` G4 (`--selftest` then real run). It does not pretend to
  run the CI-only scanners themselves; it guarantees their steps cannot be silently
  removed or downgraded. Verified here: selftest green, real run green with 7 honest
  non-blocking advisory notes (a few datastore/gateway manifests omit resource
  limits/`runAsNonRoot`; the `:latest` template tags the deploy pipeline pins to a verified
  digest). This is the self-enforcing half of Step 15; the live execution of gitleaks/
  Trivy/Semgrep/CodeQL/ZAP + cosign signing remains CI-runner-only by nature.
- **NL→SQL & IOC-credential defense-in-depth (Ask Weissman hardening).** Four layered
  gaps closed on the read-only NL→SQL and global IOC-credential paths — none was
  exploitable on its own (the app-layer allow-lists and RBAC held), but each removes a
  latent second-order risk and makes the boundary self-enforcing:
  1. **Independent AST gate on every executed NL query.** `nl_query::execute_plan` now
     runs `cem_dago::sql_ast::validate_compiled_sql_ast` on the compiled statement
     before it reaches the weissman_ro pool — a second, parser-based line behind
     `compile_plan`'s identifier allow-list that admits exactly one SELECT over
     allow-listed tables/columns, clamps LIMIT to 200, and rejects
     CTE/UNION/subquery/function/concatenation. It validates the inner statement (the
     `wrap_nl_sql` envelope adds an outer subquery the gate correctly rejects). This gate
     was already applied on the CEM-DAGO sandbox path; it now covers the `/api/ask`
     path too, so a future `compile_plan` regression fails closed.
  2. **Fail-closed weissman_ro SELECT-grant drift guard at boot.** `role_guard::assert_pool_role`
     (ReadOnly) now asserts, via `has_table_privilege`, that the NL→SQL role can SELECT
     **only** the `RO_SELECT_TABLES` allow-list. A stray `GRANT SELECT … TO weissman_ro`
     or `GRANT … TO PUBLIC` — which would let Ask Weissman read past the allow-list —
     hard-fails a production boot (warns in dev), mirroring the existing tenant-GUC drift
     guard. Verified against live Postgres: an over-grant is detected, and clears once
     the table is allow-listed.
  3. **Blind-oracle / rate guard wired to `/api/ask`.** `ask_oracle_guard::admit_ask` — a
     fully-implemented, tested per-user burst limit (10/min, Redis fail-closed in prod)
     and enumeration detector (sequential "starts with A/B/C" walks, one-letter-flip
     membership probes) — was dead code: the handler never called it. It now runs before
     the daily quota, so an abusive client-name enumeration scan is rejected without even
     consuming the tenant's 50/day allowance.
  4. **IOC feed-credential writes moved behind a SECURITY DEFINER function.** The global
     `ioc_feed_credentials` table (AES-256-GCM envelopes of the platform's abuse.ch / OTX
     / MISP keys) granted `weissman_app` full INSERT/UPDATE/DELETE, so any app-role code
     path or SQL sink could mass-delete the secrets or forge `updated_by`/`updated_at`.
     New migration `20260920140000` (mirrored to both trees) revokes that DML and routes
     the single admin-gated writer through `set_ioc_feed_credential(...)` — a SECURITY
     DEFINER function (EXECUTE revoked from PUBLIC, granted only to weissman_app) that
     enforces the safe upsert shape (server-derived `updated_at`, no DELETE, non-empty
     key). weissman_app keeps SELECT for the process-cache refresh. Verified against live
     Postgres: direct INSERT/DELETE as weissman_app is denied, the function succeeds, and
     SELECT still works.
- **Integrity lock: no randomness in the finding scoring/persist path.** New CI gate
  `scripts/verify_no_rand_in_scoring.mjs` fails the build if `findings_persist.rs`,
  `findings_gate.rs` or `intel_epss.rs` ever import or use a randomness source
  (`rand`, `thread_rng`, `gen_range`, `StdRng`/`SmallRng`/`OsRng`, `fastrand`,
  `getrandom`). These modules compute the severity / risk_score / EPSS / KEV / proof
  that reach the `vulnerabilities` table, so this makes the headline "no fabricated or
  randomised findings" claim a build-enforced property rather than a convention (a
  reviewed non-scoring use may opt out with a `// no-rand-gate: allow` marker). The
  `findings_gate.rs` module docs are corrected to state honestly what the gate does
  (enforces non-empty proof + determinism) and does **not** (verify probe-provenance —
  that is an engine-level convention). _Deferred to its own reviewed change:_ requiring
  a structured, machine-checkable evidence object for actionable severities, because
  rejecting a real engine's prose-only finding would silently lose a genuine
  vulnerability and needs per-engine evidence-shape analysis + staging first.
- **Fail-closed boot guards against role/RLS drift.** Two hardenings in
  `crates/weissman-db/src/role_guard.rs`:
  - `assert_pool_role` now also scans `pg_db_role_setting` for a DB-/role-level
    default of `app.current_tenant_id` and, in production, **hard-fails the boot** if
    one exists (mirroring the existing superuser/BYPASSRLS refusals). That lingering
    role default was the exact cause of the historical production tenant leak;
    migration `20260811000100` reset it and a CI test keeps it gone, but that test
    only runs against the CI database — this closes the live-boot gap. New
    `role_guard_guc_drift` live test proves the detector reads 0 on a migrated DB and
    fires on an injected default.
  - `WEISSMAN_ALLOW_SUPERUSER_DSN` is now **inert in production** — a single env var
    can no longer silently downgrade every role/RLS guard from a hard boot failure to
    a warning. The non-production single-node fixture switch `WEISSMAN_E2E_STACK`
    still works in any environment; setting `WEISSMAN_ALLOW_SUPERUSER_DSN` in
    production now logs an error and is ignored. `nightly-e2e.yml` (which runs the
    stack as the postgres superuser under `WEISSMAN_ENV=production`) is switched to
    `WEISSMAN_E2E_STACK` accordingly.
- **Least-privilege: revoked the unused BYPASSRLS write surface + dropped a dead
  finding-write path.** `weissman_worker` is BYPASSRLS (it must claim the job bus
  across tenants) yet had been granted full CRUD on seven tenant-scoped (FORCE RLS)
  campaign/proof tables (`weissman_campaigns`, `weissman_campaign_{audit,events,steps,
  world_states,detection_gaps}`, `weissman_proof_artifacts`) — a role that bypasses
  RLS holding write on tenant tables can cross tenants with no RLS net. Those grants
  are unused (the worker binary never references campaign/proof; every such write runs
  through `begin_tenant_tx` on the NOBYPASSRLS `weissman_app` pool), so migration
  `20260920130000_least_privilege_bypassrls_and_drop_dead_fuzz.sql` revokes them. The
  same migration drops `promote_fuzz_candidate(bigint)` — a zero-caller SQL function
  that INSERTed straight into `vulnerabilities`, bypassing the Rust evidence gate.
  New live contract `crates/weissman-db/tests/bypassrls_write_grants_contract.rs`
  fails CI if any BYPASSRLS service role gains write on a FORCE-RLS table outside a
  documented control/auth-plane allowlist.
  - _Follow-up (tracked, not in this change):_ `weissman_app` still holds blanket
    INSERT/UPDATE on every table incl. `vulnerabilities`, so the "single gated write
    path" is still a Rust convention rather than a DB boundary. Moving finding writes
    behind a dedicated writer role/connection needs a runtime pool + credential change
    validated in staging, so it is deferred to its own reviewed change.
- **Customer (client) isolation backfilled onto 22 tenant tables that shipped
  without it** — `c2_covert_channel_audits`, `finding_candidates`, the four
  `ot_ics_*` tables, `surface_snapshots`, `vulnerability_lifecycle_events`,
  `underground_snapshots`, the `honey_route_*` and `weissman_sovereign_*` tables,
  and others created after the one-time client-scope sweeps
  (`20260826120000` / `20260826180000`). Each carried the tenant RLS predicate
  but not `weissman_client_row_visible(client_id)`, so a portal-scoped customer
  (`app.current_client_id` set) could read a **sibling customer's** rows *inside
  the same tenant* (tenant RLS does not catch cross-customer reads). Migration
  `20260920120000_client_scope_backfill_new_tables.sql` (mirrored to both
  migration trees) re-runs the idempotent, INSERT-policy-safe sweep to AND the
  visibility predicate onto every `client_id` table's policy.
- **New live RLS/client-scope contract test**
  (`crates/weissman-db/tests/rls_live_schema_contract.rs`, run in the
  `WEISSMAN_REQUIRE_DB_TESTS` CI job) introspects the **fully-migrated live
  schema** rather than migration text: it fails the build if any base table with
  a `tenant_id` column is not `ENABLE`d **and** `FORCE`d with a tenant-GUC policy
  (and no `USING (true)`), if any `client_id` table lacks the customer-visibility
  predicate, or — behaviourally — if a `weissman_app` session scoped to customer
  A can see customer B's rows. This closes the gap where the prior static
  migration-text guard could not see a disabled/`USING(true)`/wrong-column policy
  or dynamic `DO`-block DDL.
- **Removed the `genpdf` dependency** from `fingerprint_engine`, clearing the
  `RUSTSEC-2026-0187` `lopdf` deeply-nested-parse stack-overflow advisory (reached
  only via `genpdf → printpdf → lopdf`) and dropping the whole unmaintained subtree
  it pulled in — `time 0.2.x`, `stdweb`, `rusttype`, `stb_truetype`, `printpdf`,
  `lopdf`. The `RUSTSEC-2026-0187` `cargo audit` / `deny.toml` ignore is removed, so
  a reintroduction of `lopdf` now fails the build.
  - Also dropped the stale `RUSTSEC-2026-0049` ignore — that advisory is no longer
    detected on the current dependency lock (confirmed with `cargo audit`).
  - The `RUSTSEC-2026-0098/0099/0104` ignores are **removed**. Those `rustls-webpki
    0.101.7` advisories rode in on the AWS SDK's legacy `rustls 0.21` hyper-0.14
    connector, pulled by each `aws-sdk-*` crate's default `rustls` feature. Those crates
    are now declared `default-features = false` + the modern `rustls-aws-lc` connector
    (`rustls 0.23.40` / `rustls-webpki 0.103.13`), so the `rustls 0.21` subtree left the
    lock entirely; the advisories no longer resolve and a reintroduction now **fails** the
    `cargo audit` / `deny.toml` gate. The only advisory still ignored is
    `RUSTSEC-2023-0071` (rsa Marvin timing, via `openidconnect` for RS256 JWT
    verification — no fixed `rsa` release exists).
- **Executive/board PDFs now render natively** via the existing hand-written
  `%PDF-1.4` writer in `fingerprint_engine/src/pdf_report.rs` (base-14 Helvetica,
  no font embedding, no third-party PDF crate). `executive_pdf::render_executive_board_pdf`
  keeps the same public signature, so the report endpoint is unchanged.
- Dropped the now-obsolete `WEISSMAN_GENPDF_FONT_DIR` env var and the
  `fingerprint_engine/fonts/` Liberation-Sans staging directory.

---

## [2026.06.2] — Liminal Boundary Engine — 2026-06-10

### Added

- **`liminal_boundary`** — world-first protocol-stack fracture detector
  (`fingerprint_engine/src/liminal_boundary_engine.rs`):
  - **Protocol schism** — live HTTP/1.1-only vs HTTP/2 (ALPN) differential probing;
    flags auth bypasses (403→200), shadow-stack body divergence, entropy-based canary detection.
  - **Cache Vary oracle** — detects language/cookie-variant content that is publicly
    cacheable without a correct `Vary` header (personalized-content leak class).
  - **Trusted-header rewrite** — probes `X-Original-URL`, `X-Rewrite-URL`,
    `X-Forwarded-Prefix` for internal-path exposure via edge routing trust gaps.
  - Registered as production engine #254; included in baseline scan bundle; UI entry in
    Engine Matrix; aliases `protocol_schism_oracle`, `cache_vary_oracle`.
  - `reqwest` gains `http2` feature; `engine_probes` adds `http1_client`, `http2_client`,
    `http_get_with_headers`.

---

## [2026.06.0] — Autonomous-Defence Phase 3 — 2026-06-08

The rollout that converts Weissman from "advanced scanner" into a closed-loop
autonomous defence platform. All work is real and live; **zero simulation**.

### Added

#### 3.4 Financial blast-radius (`$-at-risk`)
- New module `fingerprint_engine/src/financial_risk.rs` with FAIR-aligned
  SLE/ALE math: `SLE = asset_value × max(CVSS/10, 0.5)`,
  `ALE = SLE × min(EPSS×12, 12) × discount`; KEV-listed CVEs floor ARO at 1.0/yr.
- New tables `client_asset_value_rules`, `client_financial_risk_snapshots`;
  new columns `risk_graph_nodes.business_value_usd / asset_replacement_cost_usd /
  tags`, `clients.default_asset_value_usd / risk_loss_discount`.
- Endpoints: `GET /api/financial-risk/:client_id[?recompute=1]`,
  `POST /api/financial-risk/:client_id/apply-tags`.
- `frontend/src/pages/Clients.jsx` rewritten — replaces "N critical findings"
  with `$-at-risk` hero band (SLE worst, ALE annualised, crown-jewel value,
  total asset value) plus a per-client card `$-at-risk` headline.

#### 3.3 Auto-pentest reinforcement loop
- New module `fingerprint_engine/src/pentest_memory.rs` with stable target
  fingerprint (`host + server + powered_by + sorted tech_stack`),
  `record_win(engine, cwe, sig, payload, evidence, status, target_fp)`,
  `prior_winners(engine, target_fp, K)` using HNSW ANN over `vector(1536)`
  target embeddings.
- New table `pentest_winning_paths` with `won_count`, `replay_count`,
  `replay_hit_count` so the reinforcement learning rate is measurable.

#### 3.1 Endpoint UEBA (User & Entity Behaviour Analytics)
- Agent: `crates/weissman-agent/src/detections/baseline.rs` — periodic sampler
  for open ports, top processes, unique users, load/memory, failed logins;
  hour-of-week bucket. New capability `ueba_baseline`.
- Server: `fingerprint_engine/src/ueba_detector.rs` — 7-day rolling baseline
  per `(agent, metric, hour_of_week)`, z-score detector (`|z| > 3` → `medium`,
  `> 6` → `high`), and new-port / new-process categorical detector. Strict
  learning-window contract: never fires before 24 samples in the bucket.
- New tables `agent_metric_samples`, `agent_metric_baselines`, `agent_anomalies`.
- Endpoints: `POST /api/ueba/ingest`, `GET /api/ueba/anomalies`.
- Hourly retention loop purges samples older than 14 days.

#### 3.2 Ask Weissman (NL → safe SQL)
- New module `fingerprint_engine/src/nl_query.rs` — LLM emits a strict JSON
  `QueryPlan` (never raw SQL); server validates against an allow-list of 6
  tables × ~50 columns × 10 operators, compiles to parameterised SQL with
  `tenant_id = $1` enforced, executes against the **dedicated read-only
  Postgres role** `weissman_ro` (SELECT-only, `statement_timeout=15s`,
  `idle_in_transaction_session_timeout=30s`).
- New table `nl_query_audit` records every question + compiled SQL + rows + ms.
- Endpoint: `POST /api/ask`. UI: `frontend/src/pages/AskWeissman.jsx`
  (chat-style transcript with collapsible SQL preview per turn).

### Changed

- Workspace `Cargo.toml` now includes `crates/weissman-agent`.
- `crates/weissman-db/Cargo.toml` gains `sha2`, `thiserror`, `tokio` (fs feature)
  for the no-transaction pre-runner (see 2026.06.1).
- Cockpit hero (`ExecKpiStrip` + `LiveActivityFeed` + `MitreCoverageHeatmap` +
  `SeverityTrendChart` + `TopMoversPanel`) is the default landing surface.
- `OpenAPI 3.1` spec at `/api/openapi.json` now lists every phase-1/2/3 endpoint
  with full descriptions; raise the crate `recursion_limit` to 512 for the
  inline spec macro.

---

## [2026.06.1] — Migration runner: out-of-transaction support — 2026-06-08

### Added

- `crates/weissman-db/src/no_tx_migrations.rs` — pre-runner that detects the
  `-- weissman:no-transaction` header on line 1 of a migration file, executes
  each statement outside any transaction (multi-statement-safe SQL splitter
  that respects single/double quotes, line/block comments, dollar-quoted
  blocks), records the file in `_sqlx_migrations` with the SHA-384 checksum
  format SQLx itself uses. Subsequent boots see those rows and skip.
- `crates/weissman-db/migrations/20260608150000_async_jobs_pending_partial_index.sql`
  — replaces `ix_weissman_async_jobs_pending(created_at) WHERE status='pending'`
  with `ix_async_jobs_pending(created_at, kind) WHERE status='pending'`. Worker
  hot-query went from 1.1–2.8 s (logged "slow statement" warnings) to a few ms
  index-only scan. Build is fully CONCURRENTLY — no lock on the live table.
- 11 unit tests covering header parsing (BOM tolerance, case insensitivity,
  first-line-only enforcement, rejection of non-directive first lines),
  filename parser, SQL splitter (dollar-quoted bodies, doubled `''` escape,
  line-comment-with-semicolon), and SHA-384 sanity (matches FIPS 180-4
  constant for empty input).

### Changed

- `weissman_db::run_migrations` is now two-phase: no-tx pre-runner →
  `sqlx::migrate!()`. Public signature unchanged.

---

## [2026.06.0-phase2] — Autonomous-Defence Phase 2 — 2026-06-08

### Added

- **pgvector RAG**: switched to `pgvector/pgvector:pg16` Docker image,
  `CREATE EXTENSION vector`, `supreme_council_memory.embedding_vec vector(1536)`
  with HNSW cosine index. `fingerprint_engine/src/embeddings.rs` provides an
  OpenAI-compatible `/v1/embeddings` client (works with vLLM / Ollama too).
  `council::fetch_supreme_memory_context` now retrieves top-K via real ANN
  (`<=>` operator) with full-text fallback when the embedding service is down.
- **Attack-path inference**: `fingerprint_engine/src/attack_path.rs` runs
  Dijkstra over the live `risk_graph_nodes`/`risk_graph_edges` graph from
  `internet_exposed=true` to `crown_jewel=true`, edge weights derived from each
  node's worst CVSS+EPSS+KEV; emits top-K paths + choke-points (nodes that
  appear in ≥50 % of the paths). Snapshots persisted in `attack_path_snapshots`.
- **SOAR playbooks**: `fingerprint_engine/src/soar_playbook.rs` — JSON DSL,
  trigger evaluator, idempotent action dispatcher (`set_status`,
  `slack_notify`, `webhook`, `http_post`, `open_pr`, `isolate_host`,
  `page_oncall`), `{{placeholder}}` template rendering, cooldown dedup, full
  audit in `weissman_playbook_runs`. Hooked into `findings_persist` so every
  new persisted finding evaluates against enabled playbooks.
- Endpoints: `GET /api/attack-paths/:client_id`, `PATCH /api/risk-graph/nodes/:id/flags`,
  `GET|POST /api/playbooks`, `PATCH|DELETE /api/playbooks/:id`,
  `POST /api/playbooks/fire`, `GET /api/playbooks/:id/runs`.
- UI: `frontend/src/pages/PlaybookBuilder.jsx` — three-pane visual editor
  (playbook list / trigger+actions editor / run history) with sample-event
  dry-run.

### Changed

- `Cockpit.jsx` mounts `ExecKpiStrip` as the sticky hero band.

---

## [2026.06.0-phase1] — Detection-integrity rollout — 2026-06-08

### Added

- **Threat-intel mirrors**: `intel_kev.rs` (CISA KEV refresh every 6 h) and
  `intel_epss.rs` (FIRST.org EPSS — on-demand on persist + back-fill every 12 h).
  New tables `kev_intel`, `epss_intel`; new columns on `vulnerabilities`:
  `epss_score`, `epss_percentile`, `kev_listed`, `kev_known_ransomware`,
  `kev_due_date`, `intel_enriched_at`.
- **Finding correlation/dedup**: `findings_correlator.rs` —
  `cluster_key = sha256(target | signature | cwe)` with URL normalisation
  (lowercases host, strips query / fragment / trailing slash). New table
  `weissman_finding_clusters` with aggregate `engines[]`, `sources[]`,
  `cves[]`, `max_severity`, `max_cvss`, `max_epss`, `kev_listed`.
  `vulnerabilities.cluster_id` FK + atomic upsert.
- **FP/TP feedback + auto-suppression**: `fp_feedback.rs` — Bayesian-shrinkage
  `confidence_multiplier = (tp+1)/(tp+fp+1)` clamped to `[0.1, 1.0]`,
  applied to `risk_score` at read time. Three FALSE_POSITIVE marks on the same
  `(engine, signature_hash)` add a row in `finding_suppressions`; next
  detection is silently flipped to `FALSE_POSITIVE` (audit-preserving).
- Endpoints: `GET /api/findings/clusters`, `GET /api/intel/status`,
  `GET /api/intel/suppressions`, `DELETE /api/intel/suppressions/:id`.
- `/api/findings` now returns `epss_score`, `epss_percentile`, `kev_listed`,
  `kev_known_ransomware`, `kev_due_date`, `cluster_id`, `signature_hash`,
  `confidence_multiplier`, `seen_count`. Default sort:
  `KEV → EPSS → discovered_at`.

### Fixed

- **Stable `finding_id` hash** — used to be SHA-256 of the entire payload
  (including timestamps), so the same vulnerability re-detected by the same
  engine on the same target produced a *new* row every scan. Now hashes only
  invariants: `engine | target | cve | cwe | mitre | signature | normalised_title`.
- **Real dedup** — `UNIQUE (tenant_id, client_id, finding_id)` enforced;
  `ON CONFLICT DO UPDATE` refreshes evidence + bumps `seen_count`. Analyst-set
  status (ACKNOWLEDGED / FIXED / FALSE_POSITIVE) is preserved across re-scans.
- **PoE job registry leak** — `serve.rs` previously kept disconnected SSE
  subscriber slots in the DashMap forever. Now removed when the entry's
  sender list becomes empty.
- **`api_audit_logs`** — paginated, filterable, server-side; previously
  hard-capped at 500 with no filter.
- **`is_scanning_active` race** — split into operator toggle vs. live
  `scan_in_progress()` derived from `ACTIVE_TENANT_CYCLES` counter; `/api/health`
  now exposes both.
- **Constant-time bearer comparison** in `cicd_interceptor` (was using `==`,
  vulnerable to timing leak). Now uses `subtle::ConstantTimeEq` with length pad.

---

## [2026.06.0-foundations] — Cockpit + onboarding polish — 2026-06-02

### Added

- Branded SVG logo + favicon set.
- Global toast notification system (`Toaster`), skeleton loaders, empty-state
  component, keyboard-shortcut overlay (`?` for help, `g+h/e/f/v/a/c/j/s`
  to navigate), profile menu (avatar + role + language + sign-out), branded
  404 page, finding-detail drawer.
- Audit-log viewer page + nav entry.
- Self-serve signup (`/api/auth/signup` → email-verify → tenant + admin user).
  Gated by `WEISSMAN_SELF_SERVE_SIGNUP=true`. UI: `deploy/public/signup.html`.
- OpenAPI 3.1 + Swagger UI at `/api/docs/`.
- Public marketing site: `/`, `/pricing.html`, `/terms.html`, `/privacy.html`,
  `/dpa.html`, `/security-policy.html`, `/.well-known/security.txt`,
  `/robots.txt`, `/sitemap.xml`.
- Production security headers across every nginx location: HSTS, CSP,
  X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy,
  Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy.

---

## [2026.05.20] — Last pre-autonomous-defence release

Baseline of 47 tests + 188 routes + the original "engine-room" cockpit.
