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

## Self-repair loop

`auto_heal_job::run_auto_heal_job` verifies, and on any non-`Fixed` verdict feeds the failure
reason (still-vulnerable / broke-app / didn't-apply, plus the sandbox error and the files the last
patch touched) back to `remediation_patch::regenerate_patch`. The regenerated diff is re-validated
(`security_hardening::validate_remediation_patch`) and re-verified, up to `WEISSMAN_HEAL_MAX_ATTEMPTS`
(default 3). Temperature climbs per attempt. Every attempt streams a step into
`heal_verification_steps`, so the UI shows the whole journey. The winning patch is persisted.

## Delivery channels (`heal_channels::DeliveryChannel`)

All channels reuse the single verified `changed_files` artifact.

| id                     | Effect                                                             |
|------------------------|-------------------------------------------------------------------|
| `github_pr` (default)  | Commit the applied files to a branch, open a GitHub PR            |
| `github_direct_commit` | Commit the applied files to a branch, no PR                       |
| `gitlab_mr`            | Commit + open a GitLab Merge Request (v4 API, `PRIVATE-TOKEN`)    |
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

## API

| Method     | Path                                                | Purpose                                  |
|------------|-----------------------------------------------------|------------------------------------------|
| POST       | `/api/clients/:id/auto-heal`                        | Start a heal (operator + dual-auth)      |
| GET/POST   | `/api/clients/:id/findings/:finding_id/brief`       | Bilingual (he/en) remediation brief      |
| GET        | `/api/heal-verify/:job_id/steps`                    | Live verification timeline               |
| GET        | `/api/heal-verify/:job_id`                          | Status + verdict + PR + attempts         |
| GET        | `/api/heal-verify/:job_id/patch`                    | Download the verified diff / WAF snippet |
| GET        | `/api/heal-verify/:job_id/attestation`              | Verify the signed heal receipt           |
| GET        | `/api/clients/:id/heal-stats`                       | Aggregate heal analytics                 |
| GET        | `/api/clients/:id/heal-requests`                    | Heal request history                     |

## Environment variables

| Variable                                | Default        | Effect                                            |
|-----------------------------------------|----------------|---------------------------------------------------|
| `WEISSMAN_HEAL_MAX_ATTEMPTS`            | `3`            | Self-repair loop attempt cap (1–10)               |
| `WEISSMAN_HEAL_DEDUP_HOURS`             | `24`           | Duplicate-PR dedup window (0 disables)            |
| `WEISSMAN_VERIFY_REQUIRE_BEFORE_SUCCESS`| `1`            | Require baseline exploit to be 2xx                |
| `WEISSMAN_VERIFY_REQUIRE_HEALTH`        | `1`            | Require post-patch health probe to pass           |
| `WEISSMAN_VERIFY_RUN_TESTS`             | `0`            | Opt-in in-container regression test gate          |
| `WEISSMAN_VERIFY_MEM_MB` / `_CPUS` / `_PIDS` | `1024`/`1.0`/`512` | Sandbox resource caps                    |
| `WEISSMAN_GITLAB_HOST`                  | `gitlab.com`   | GitLab host for the `gitlab_mr` channel           |
| `WEISSMAN_ATTESTATION_KEY`              | (derived)      | HMAC key for signed heal receipts                 |
| `WEISSMAN_REGRESSION_ALERT`             | on             | Fire an alert when a fixed finding reopens        |
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
