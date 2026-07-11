# Autonomous Auto-Heal

Weissman's self-healing subsystem takes a detected vulnerability and drives it to a **proven,
non-regressing, cryptographically-attested fix** — then delivers that fix through the channel the
operator chooses. It is designed so the fix that lands is the fix that was verified, and the claim
that it was verified is provable.

## End-to-end flow

```
finding ──▶ generate patch (LLM "vaccine")
             │
             ▼
     ┌─────────────────────── self-repair loop (≤ N attempts) ───────────────────────┐
     │  verify_patch_ephemeral_docker:                                                │
     │    shallow-clone repo → ephemeral hardened Docker container (bind-mount /app)  │
     │    baseline exploit probe (must be 2xx / vulnerable)                           │
     │    apply patch on host clone → capture the ACTUAL changed files                │
     │    restart container                                                           │
     │    re-run exploit + health probe (+ optional regression tests)                 │
     │    ── verdict ──────────────────────────────────────────────────────────────  │
     │       Fixed | StillVulnerable | BrokeApp | Inconclusive                        │
     │    if not Fixed → feed the failure back to the LLM, regenerate, re-verify      │
     └───────────────────────────────────────────────────────────────────────────────┘
             │ Fixed
             ▼
   secret-safety gate → idempotency (dedup) → sign heal receipt → DELIVER via channel
             │
             ▼
   metrics + tenant completion notification
```

## Verdict model (`verification_sandbox::HealVerdict`)

The verdict is a real oracle, not "the response changed":

| Verdict           | Meaning                                                              | Opens PR |
|-------------------|---------------------------------------------------------------------|:--------:|
| `Fixed`           | Baseline was exploitable, exploit now blocked (3xx/4xx), app healthy | ✅       |
| `StillVulnerable` | Exploit still returns 2xx                                            | ❌       |
| `BrokeApp`        | Exploit route 5xx/unreachable, or health probe failed, or tests regressed | ❌  |
| `Inconclusive`    | Baseline never proven, or patch didn't apply                        | ❌       |

Only `Fixed` is delivered. A patch that merely crashes the endpoint is `BrokeApp`, never a "fix".

## Candidate tournament (opt-in)

When `WEISSMAN_HEAL_TOURNAMENT_SIZE ≥ 2`, the pipeline first runs a **tournament**: it generates
several *diverse* candidate patches — each from a different fix strategy (minimal, root-cause input
validation, safe-API, defense-in-depth, framework-layer; `remediation_patch::CANDIDATE_STRATEGIES`) —
plus the pre-generated seed patch, verifies each in the sandbox, and **seeds the pipeline with the
best proven candidate**. The winner is chosen by `score_result`: verdict quality first (`Fixed` >
`StillVulnerable` > `Inconclusive` > `BrokeApp`), then a tests-passed bonus, then the **smallest
change** (fewest files, then fewest bytes) — i.e. the cleanest proven fix. If the winner is already
`Fixed` it is delivered; otherwise the self-repair loop refines from it.

## Self-repair loop

`auto_heal_job::run_auto_heal_job` verifies, and on any non-`Fixed` verdict feeds the failure
reason (still-vulnerable / broke-app / didn't-apply, plus the sandbox error and the files the last
patch touched) back to `remediation_patch::regenerate_patch`. The regenerated diff is re-validated
(`security_hardening::validate_remediation_patch`) and re-verified, up to `WEISSMAN_HEAL_MAX_ATTEMPTS`
(default 3, shared with the tournament budget). Temperature climbs per attempt. Every attempt streams
a step into `heal_verification_steps`, so the UI shows the whole journey. The winning patch is persisted.

## Delivery channels (`heal_channels::DeliveryChannel`)

All channels reuse the single verified `changed_files` artifact.

| id                     | Effect                                                             |
|------------------------|-------------------------------------------------------------------|
| `github_pr` (default)  | Commit the applied files to a branch, open a GitHub PR            |
| `github_direct_commit` | Commit the applied files to a branch, no PR                       |
| `gitlab_mr`            | Commit + open a GitLab Merge Request (v4 API, `PRIVATE-TOKEN`)    |
| `bitbucket_pr`         | Commit via `/src` + open a Bitbucket Cloud PR (v2 API, Bearer token) |
| `azure_repos_pr`       | Push + open an Azure DevOps PR (v7 API, PAT via Basic auth)       |
| `diff_download`        | No repo mutation; serve the verified unified diff for manual apply |
| `virtual_patch`        | No repo mutation; render a WAF/ModSecurity compensating rule      |

The verification sandbox clones provider-aware (GitHub `x-access-token`, GitLab `oauth2`).

## Trust: signed heal receipts (`heal_attestation`)

On a `Fixed` outcome the platform signs an HMAC-SHA256 receipt over
`{finding_id, verdict, baseline_status, after_status, exploit_hash, changed_files_hash, ts}`,
reusing the platform attestation key (`finding_attestation`). The receipt + digest are stored on
`heal_requests`, referenced in the PR body, and independently verifiable at
`GET /api/heal-verify/:job_id/attestation`. In dev (no `WEISSMAN_ATTESTATION_KEY`) signing is skipped
— nothing is faked.

## Safety gates

- **Secret gate** — `engine_probes::detect_secrets` scans every changed file; a fix that embeds a
  secret (`ghp_`/`glpat-`/AWS/…) is blocked, never committed.
- **Idempotency** — an existing verified heal PR/MR for the same finding within
  `WEISSMAN_HEAL_DEDUP_HOURS` (default 24) is reused instead of opening a duplicate.
- **Hardened sandbox** — the container runs with memory/CPU/pids caps, `cap_drop: ALL`, and
  `no-new-privileges`.
- **RBAC** — the mutating endpoint requires operator role and destructive/dual-approval headers.

## Governance (advisory disposition)

The pure `heal_policy` module computes a **recommended disposition** for every completed heal and a
bilingual (he/en) rationale, surfaced on the HTML report, `report.json`, and the SARIF properties:

| disposition       | when                                                                        |
|-------------------|-----------------------------------------------------------------------------|
| `block`           | verdict `broke_app` (unless `heal_allow_broke_app_delivery`)                 |
| `hold`            | any non-`fixed` verdict (still-vulnerable / inconclusive / pending)          |
| `auto_merge`      | verified `fixed`, within the tenant's auto-merge risk envelope               |
| `open_for_review` | verified `fixed`, but outside the envelope (severity / attestation / attempts) |

Per-tenant policy lives in `system_configs` (safe defaults shown): `heal_auto_merge_max_severity`
(`low`), `heal_require_attestation_for_merge` (`true`), `heal_max_attempts_for_merge` (`3`),
`heal_allow_broke_app_delivery` (`false`).

**Enforcement (opt-in).** By default the disposition is advisory. When `WEISSMAN_HEAL_AUTO_MERGE=1`
(hard opt-in, default off), a freshly opened **GitHub-PR** heal that the policy rates `auto_merge` —
i.e. a verified, **attested**, within-envelope fix — is squash-merged automatically
(`auto_heal::merge_pull_request`), and its `heal_requests` row flips to `auto_merged`. Everything else
stays a PR for human review. The merge is best-effort and never fails the heal; `broke_app`/`hold`
outcomes are never auto-merged, and with no attestation key nothing auto-merges (attestation is
required by default).

## Closed loop

`remediation_verify::run_verification` re-runs the same engine against the same target and promotes
the finding to `VERIFIED_FIXED` or `REOPENED`. On `REOPENED` (regression) it fires
`alert_delivery::notify_regression`; a SOAR playbook can turn that signal into an autonomous re-heal.

## Observability

- `/api/metrics` (Prometheus): `weissman_heal_total{verdict,channel,ok}`,
  `weissman_heal_duration_seconds{channel}`, `weissman_heal_by_verdict{verdict}`,
  `weissman_heal_success_rate`, `weissman_heal_total_requests`.
- `GET /api/clients/:id/heal-stats`: total, verdict distribution, success rate, avg/max attempts,
  attested count, per-channel breakdown (surfaced as a strip on the Remediation Hub).
- Completion notifications (webhook / Slack / PagerDuty) via `alert_delivery::notify_heal_completed`.
  Outbound webhook payloads are **signed**: each carries `X-Weissman-Digest` (sha256 of the exact
  body) and, when an attestation key is set, `X-Weissman-Signature: v1=<hmac>` (same key/scheme as the
  signed heal receipts) — a receiver verifies by re-hashing the raw body and checking the HMAC, so a
  forged or tampered notification is detectable.
- **Auto Slack post on completion** (`alert_delivery::post_heal_slack`, `WEISSMAN_SLACK_HEAL_NOTIFY`, on by
  default): every finished heal posts a Block Kit summary to the tenant's Slack (webhook or
  `chat.postMessage`). On a `Fixed` outcome that opened a PR/MR it posts the **interactive
  Approve/Dismiss** blocks (HMAC-signed action values, verified by the interactivity endpoint); otherwise
  a plain verdict summary. Best-effort and fire-and-forget — it never blocks or fails the heal.

## UI

- **Remediation Hub** (`/remediation`) — workflow board + heal-stats strip.
- **Remediation Analytics** (`/remediation-analytics`) — a dedicated routed dashboard that aggregates
  `heal-stats` across every active client (`RemediationAnalyticsPanel`) and a merged, newest-first
  **recent-heals** activity feed from `/api/clients/:id/heal-requests`. It also surfaces the
  **auto-heal readiness** self-diagnostics panel (`HealReadinessPanel`, `GET /api/heal-readiness`):
  a bilingual (he/en), scored (0–100) preflight of every pipeline capability — LLM synthesis and the
  verification sandbox (both required), plus signed receipts, autonomous GitHub PRs, Slack approvals,
  and LLM auth (recommended/optional) — where each missing capability shows exactly how to connect it.
  The endpoint returns only presence booleans + guidance, never any secret value; the pure
  `heal_readiness::evaluate_readiness` scorer is fully unit-tested.
- **Remediation Detail** — per-finding self-repair timeline, verified-receipt badge, channel picker,
  and a **Remediation report** link (any completed heal) that opens a self-contained, printable
  bilingual (he/en) HTML report at `GET /api/heal-verify/:job_id/report` — the finding, the bilingual
  problem/root-cause/impact/fix explanation, the verified diff + changed files, per-channel how-to-apply,
  and an honestly-labelled signed-receipt seal. Rendered by the pure `remediation_report` module
  (every untrusted value HTML-escaped, `http(s)`-only links, zero external resources). Alongside it,
  **JSON** and **SARIF** links expose the same proof machine-readably: `report.json`
  (`weissman-heal-report/v1`) for programmatic/CI consumption and a **SARIF 2.1.0** document
  (`GET …/sarif`) that ingests straight into GitHub code scanning / SAST dashboards — both rendered by
  the pure, unit-tested `heal_export` module from a single shared `load_heal_report_data` query pass.

## CI integration

A ready-to-use GitHub Action lives at [`docs/ci/upload-heal-sarif.yml`](ci/upload-heal-sarif.yml):
copy it into a consumer repo's `.github/workflows/`, set the `WEISSMAN_BASE_URL` and
`WEISSMAN_API_TOKEN` secrets, and it pulls `GET /api/heal-verify/:job_id/sarif` and uploads it to
GitHub code scanning via `github/codeql-action/upload-sarif` (`security-events: write`). Trigger it
manually with a job id, or wire your completion webhook to fire a `repository_dispatch`
(`weissman_heal_completed`, `client_payload.job_id`) so a verified heal lands in the repo's Security
tab automatically.

## Round-trip integration tests

`fingerprint_engine/tests/auto_heal_roundtrip.rs` exercises the real host-side pipeline end to end
without requiring a Docker socket:

- **git/patch** — `apply_unified_patch` + `collect_changed_files` over a real temp git repo
  (modify/add/rename/delete), plus the no-change error path.
- **probe → verdict** — a raw `tokio` TCP server drives the real `http_probe` + `classify_verdict` for
  `Fixed` / `StillVulnerable` / `BrokeApp` (5xx and health-down) / connection-refused, and
  `rewrite_localhost_url` host/port mapping.
- **curl parsing** round-trip.
- **Docker E2E** (`docker_full_roundtrip_verify_patch_ephemeral`) is gated behind `WEISSMAN_IT_DOCKER=1`
  and self-skips when no Docker socket is present (as in the sandbox). It uses
  `WEISSMAN_VERIFY_CLONE_URL_OVERRIDE` to point the sandbox clone at a local `file://` repo.

## API

| Method     | Path                                                | Purpose                                  |
|------------|-----------------------------------------------------|------------------------------------------|
| POST       | `/api/clients/:id/auto-heal`                        | Start a heal (operator + dual-auth)      |
| POST       | `/api/clients/:id/heal-revert`                      | Close (revert) an auto-opened PR/MR       |
| GET/POST   | `/api/clients/:id/findings/:finding_id/brief`       | Bilingual (he/en) remediation brief      |
| GET        | `/api/heal-verify/:job_id/steps`                    | Live verification timeline               |
| GET        | `/api/heal-verify/:job_id`                          | Status + verdict + PR + attempts         |
| GET        | `/api/heal-verify/:job_id/patch`                    | Download the verified diff / WAF snippet |
| GET        | `/api/heal-verify/:job_id/attestation`              | Verify the signed heal receipt           |
| GET        | `/api/heal-verify/:job_id/report`                   | Printable bilingual (he/en) HTML report  |
| GET        | `/api/heal-verify/:job_id/report.json`              | Machine-readable heal proof (`weissman-heal-report/v1`) |
| GET        | `/api/heal-verify/:job_id/sarif`                    | SARIF 2.1.0 for GitHub code scanning / SAST |
| GET        | `/api/heal-readiness`                               | Bilingual pipeline readiness self-check  |
| GET        | `/api/clients/:id/heal-stats`                       | Aggregate heal analytics                 |
| GET        | `/api/clients/:id/heal-trends?days=30`              | Daily trend/SLA analytics (volume, success rate, attempts) |
| GET        | `/api/clients/:id/heal-priorities?limit=50`         | OPEN findings ranked by auto-heal priority (P0–P3) |
| POST       | `/api/clients/:id/heal-batch`                       | Batch-heal many findings at once          |
| GET        | `/api/clients/:id/heal-stats`                       | (also feeds the visual analytics panel)   |
| GET        | `/api/clients/:id/heal-requests`                    | Heal request history                     |
| POST       | `/api/integrations/slack/interactivity`             | Slack Approve/Dismiss callback (signed)   |

## Environment variables

| Variable                                | Default        | Effect                                            |
|-----------------------------------------|----------------|---------------------------------------------------|
| `WEISSMAN_HEAL_MAX_ATTEMPTS`            | `3`            | Total generation budget (tournament + self-repair, 1–10) |
| `WEISSMAN_HEAL_TOURNAMENT_SIZE`         | `1`            | Candidate tournament size (≥2 enables it, max 6)  |
| `WEISSMAN_HEAL_TOURNAMENT_CONCURRENCY`  | `2`            | Max candidates verified in parallel (1–6)         |
| `WEISSMAN_HEAL_DEDUP_HOURS`             | `24`           | Duplicate-PR dedup window (0 disables)            |
| `WEISSMAN_HEAL_AUTO_MERGE`              | off            | Opt-in: auto-merge policy-`auto_merge` GitHub PRs |
| `WEISSMAN_VERIFY_REQUIRE_BEFORE_SUCCESS`| `1`            | Require baseline exploit to be 2xx                |
| `WEISSMAN_VERIFY_REQUIRE_HEALTH`        | `1`            | Require post-patch health probe to pass           |
| `WEISSMAN_VERIFY_RUN_TESTS`             | `0`            | Opt-in in-container regression test gate          |
| `WEISSMAN_VERIFY_MEM_MB` / `_CPUS` / `_PIDS` | `1024`/`1.0`/`512` | Sandbox resource caps                    |
| `WEISSMAN_GITLAB_HOST`                  | `gitlab.com`   | GitLab host for the `gitlab_mr` channel           |
| `WEISSMAN_ATTESTATION_KEY`              | (derived)      | HMAC key for signed heal receipts                 |
| `WEISSMAN_REGRESSION_ALERT`             | on             | Fire an alert when a fixed finding reopens        |
| `WEISSMAN_HEAL_DEDUP_HOURS`             | `24`           | (also above) duplicate-PR window                  |
| `WEISSMAN_SLACK_SIGNING_SECRET`         | (unset)        | Enables the Slack interactivity approval endpoint |
| `WEISSMAN_SLACK_HEAL_NOTIFY`            | on             | Auto-post a Slack summary (interactive approval on Fixed+PR) when a heal finishes |
| `WEISSMAN_VERIFY_CLONE_URL_OVERRIDE`    | (unset)        | Override the sandbox clone URL (used by round-trip integration tests) |
| `WEISSMAN_IT_DOCKER`                    | `0`            | Set to `1` to run the Docker-gated end-to-end round-trip integration test |
| `WEISSMAN_AUTOHEAL_REPO`                | (unset)        | Default repo for Slack-approved / config-less heals |
| `WEISSMAN_AUTOHEAL_SKIP_SANDBOX`        | `0`            | Legacy advisory path (unverified) — testing only  |

## Key modules

- `fingerprint_engine/src/verification_sandbox.rs` — sandbox, verdict, applied-fix capture, tests
- `fingerprint_engine/src/auto_heal_job.rs` — orchestrator, self-repair loop, delivery, dedup
- `fingerprint_engine/src/remediation_patch.rs` — LLM patch regeneration
- `fingerprint_engine/src/remediation_brief.rs` — bilingual brief
- `fingerprint_engine/src/heal_channels.rs` — channel model + virtual-patch renderer
- `fingerprint_engine/src/heal_attestation.rs` — signed receipts
- `fingerprint_engine/src/gitlab_heal.rs` — GitLab MR client
- `fingerprint_engine/src/auto_heal.rs` — GitHub PR client
