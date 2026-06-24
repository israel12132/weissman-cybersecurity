# 18 — QA & Verification (Pre-Delivery)

## Purpose

Sign-off checklist before customer handoff or production go-live. Validates engine wiring, UI completeness, security guards, and end-to-end scan workflows using repository verification scripts and manual smoke tests.

---

## Prerequisites

- Staging environment mirroring production config
- `WEISSMAN_ENV=production` on staging (recommended)
- Strong secrets (not dev defaults)
- Docker Compose, systemd, or K8s deployment complete
- Operator admin account with MFA tested

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

Expected: **545 production engines**, 0 wiring wiring gaps.

### 2. Engine reality audit

```bash
node scripts/engine_reality_audit.mjs
```

**Pass criteria:** Zero `no_path` engines.

Reports counts by kind: `real_probe`, `agent_required`, `alias`, `special`.

### 3. UI compliance audit

```bash
node scripts/weissman-ui-audit.mjs
```

**Pass criteria:** All Command Center pages pass evidence, refresh, export, and search rules.

Expected: **94/94 pages** compliant (per sales readiness audit).

### 4. Rust build and tests

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace
```

### 5. Frontend build

```bash
cd frontend && npm ci && npm run build
```

---

## Security verification

| Check | Procedure | Pass |
|-------|-----------|------|
| Production guards | Start with weak JWT → must refuse boot | Boot blocked |
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

1. One `real_probe` (e.g., `dns_recon`)
2. One `agent_required` — confirm honest empty before agent, findings after agent online

### Agent (if in scope)

- [ ] `GET /install/agent.sh` returns script
- [ ] Agent installs and shows online
- [ ] Agent engine produces host finding

### Reports

- [ ] CSV export downloads with data
- [ ] PDF report generates

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
  [ ] verify_engine_wiring.mjs — 0 gaps
  [ ] engine_reality_audit.mjs — 0 no_path
  [ ] weissman-ui-audit.mjs — all pages pass
  [ ] cargo test — pass
  [ ] frontend build — pass

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
2. Run scripts 1–3 above
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
