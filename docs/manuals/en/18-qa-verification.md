# 18 — QA & Verification (Pre-Delivery)

## Purpose

Sign-off checklist before customer handoff or production go-live. Validates engine wiring, UI completeness, security guards, end-to-end scan workflows, and **audit evidence** using repository verification scripts and manual smoke tests.

---

## Prerequisites

- Staging environment mirroring production config
- `WEISSMAN_ENV=production` on staging (recommended)
- Strong secrets: JWT **≥48 characters**; metrics / destructive / job-orchestrator **≥32 characters**
- Docker Compose, systemd, or K8s deployment complete
- Operator admin account with MFA tested

---

## Master gate — run first

```bash
bash scripts/full_audit_gate.sh
```

**Pass criteria:** Exit code 0, message `GLOBAL PASS`. Aggregates G1–G7:

| Gate | Command | Criterion |
|------|---------|-----------|
| G1 Build | `cargo build --workspace && cd frontend && npm run build` | Exit 0 |
| G2 Tests | `cargo test --workspace && cd frontend && npm run test:coverage` | 0 failures; ≥60% critical-path coverage |
| G3 Lint | `cargo clippy --workspace && cargo fmt --check` | 0 errors |
| G4 Wiring | `node scripts/verify_engine_wiring.mjs` | 0 gaps |
| G5 Reality | `node scripts/engine_reality_audit.mjs` | 0 `no_path` |
| G6 Migrations | `bash scripts/check-migration-sync.sh` | PASS |
| G7 Live + evidence | UI audit, evidence pack, go-live check, optional live E2E | All pass |

---

## Automated verification scripts

Run from repository root after build:

### 1. Engine wiring audit

```bash
node scripts/verify_engine_wiring.mjs
```

**Pass criteria:** Exit code 0, zero gaps.

Validates:

- Every UI engine in `enginesRegistry.js` exists in `PRODUCTION_ENGINE_IDS`
- Every production engine has dispatch or alias runner path
- No orphan frontend IDs

Expected: **563 production engine IDs**, 0 wiring gaps.

### 2. Engine reality audit

```bash
node scripts/engine_reality_audit.mjs
```

**Pass criteria:** Zero `no_path` engines.

Reports counts by kind: **300** `real_probe`, **213** `alias`, **45** `agent_required`, **0** `special`.

### 3. UI compliance audit

```bash
node scripts/weissman-ui-audit.mjs
```

**Pass criteria:** All Command Center pages pass evidence, refresh, export, and search rules.

Expected: **111/111 pages** compliant, **130 routes** (target ≥112).

### 4. Rust build and tests

```bash
cargo build --workspace
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D clippy::correctness -D clippy::suspicious
```

### 5. Frontend build and tests

```bash
cd frontend && npm ci && npm run build
cd frontend && npm run test:coverage
```

Expected: **67+** unit test files; coverage gate on critical lib/hooks paths.

### 6. Playwright live E2E (Phase 6)

```bash
./scripts/run_playwright_live_e2e.sh
```

Journey: login → client → scan → findings with evidence → PDF export. Requires live stack (`run_e2e_stack.sh`) and `WEISSMAN_ADMIN_PASSWORD`.

### 7. Audit evidence pack (Phase 6)

```bash
./scripts/generate_audit_evidence_pack.sh
```

Outputs `evidence-pack/*/evidence-pack.json` + PDF (wiring, SBOM hash, NIST/SOC2 mapping).

### 8. Go-live readiness

```bash
./scripts/go_live_check.sh
./scripts/go_live_check.sh --live https://staging.example.com
```

### 9. Staging QA (one command)

```bash
chmod +x scripts/staging-qa.sh
./scripts/staging-qa.sh
./scripts/staging-qa.sh --live http://localhost
```

See manual **19** for Paddle, SMTP, LLM, OAST, agent binaries, and Docker staging overlay.

---

## Security verification

| Check | Procedure | Pass |
|-------|-----------|------|
| Production guards | Start with JWT < 48 chars → must refuse boot | Boot blocked |
| Secure cookies | `WEISSMAN_COOKIE_SECURE=1` + HTTPS login | Cookie flags Secure |
| Metrics protected | `GET /api/metrics` without token → 401 | 401 |
| Destructive gate | Action without confirm header → 403 | 403 |
| Default admin rotated | Login with env default password fails | Password changed |
| Billing strict | Scan without subscription blocked (if strict on) | Quota error |

Reference manual **05**.

---

## Functional smoke tests

### Authentication

- [ ] `POST /api/login` succeeds at `/command-center/login`
- [ ] `GET /api/auth/me` returns admin role
- [ ] MFA enroll + verify flow works
- [ ] Logout clears session
- [ ] Viewer cannot run scans (403)
- [ ] Operator can run scans

### Client and billing

- [ ] Create client with authorized domains
- [ ] Billing page shows plan/usage
- [ ] Client create respects `max_clients` when strict billing on

### Scan pipeline

- [ ] `POST /api/command-center/scan` enqueues job
- [ ] Worker claims job within 60 seconds
- [ ] Findings appear in Findings Command Center
- [ ] Job completes with status `completed`

Test engines:

1. One `real_probe` (e.g., `osint`, `dns_recon`)
2. One `agent_required` — confirm honest empty before agent, findings after agent online

### Agent (if in scope)

- [ ] `GET /install/agent.sh` returns script
- [ ] Agent installs and shows online
- [ ] Agent engine produces host finding

### Reports

- [ ] CSV export downloads with data
- [ ] PDF report generates
- [ ] `GET /api/compliance/evidence-pack/:client_id` returns v2 pack

### Integrations (if sold)

- [ ] CI webhook enqueues scan
- [ ] Alert webhook fires on test rule

### SSO (if sold)

- [ ] OIDC or SAML login completes
- [ ] Role mapping correct

---

## Infrastructure checks

```bash
curl -sf https://staging.example.com/api/health
curl -sf https://staging.example.com/command-center/
docker compose ps    # all healthy
# or systemctl status weissman.target
```

- [ ] Postgres backups configured and tested
- [ ] Redis reachable when multi-replica
- [ ] TLS certificate valid
- [ ] Legal pages reachable (`/terms.html`, `/privacy.html`, `/dpa.html`)

Optional monitoring profile:

```bash
docker compose --profile monitoring up -d
# Prometheus scrapes /api/metrics with Bearer token
```

---

## Performance baseline

Record for capacity planning:

| Metric | Target (staging) |
|--------|-------------------|
| Health API p95 | < 200 ms |
| Scan job claim latency | < 30 s |
| Light engine completion | < 5 min (typical recon) |
| Concurrent light jobs | Matches `WEISSMAN_WORKER_LIGHT_CONCURRENCY` |

---

## Sign-off document

Complete before customer delivery:

```
Customer: _______________
Environment URL: _______________
Date: _______________
Engineered by: _______________

Automated:
  [ ] full_audit_gate.sh — GLOBAL PASS
  [ ] verify_engine_wiring.mjs — 563 engine IDs, 0 gaps
  [ ] engine_reality_audit.mjs — 0 no_path
  [ ] weissman-ui-audit.mjs — 111 pages, 130 routes
  [ ] generate_audit_evidence_pack.sh — JSON + PDF
  [ ] cargo test — pass
  [ ] frontend test:coverage — pass

Manual smoke:
  [ ] Login + MFA
  [ ] Client create + scan + findings
  [ ] Agent (if scope)
  [ ] PDF export
  [ ] Security guards verified

Approved by: _______________
```

Archive sign-off with engagement records.

---

## Regression after upgrades

After every production upgrade:

1. `git pull` + rebuild
2. `bash scripts/full_audit_gate.sh`
3. Health check + one smoke scan
4. Review migration logs

---

## Related manuals

- [00-sales-delivery-readiness](00-sales-delivery-readiness.md)
- [05-production-security](05-production-security.md)
- [09-client-onboarding](09-client-onboarding.md)
- [10-scans-engines-jobs](10-scans-engines-jobs.md)
- [16-operations-monitoring](16-operations-monitoring.md)
- [17-troubleshooting](17-troubleshooting.md)
- [Inspection Day Runbook](../../operations/INSPECTION-DAY-RUNBOOK.md)
