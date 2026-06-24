# 18 — QA & Verification (קבלה לפני מסירה)

## מטרה

רשימת sign-off לפני handoff ללקוח או go-live production. מאמת wiring wiring UI, guards, smoke end-to-end.

---

## דרישות מקדימות

- staging כ-production
- `WEISSMAN_ENV=production` (מומלץ)
- סודות חזקים
- פריסה מלאה (Docker/systemd/K8s)
- admin + MFA נבדק

---

## סקריפטים אוטומטיים

משורש המאגר:

### 1. Engine wiring

```bash
node scripts/verify_engine_wiring.mjs
```

**Pass:** exit 0, אפס gaps. **545 מנועים**, UI ↔ `PRODUCTION_ENGINE_IDS` ↔ dispatch.

### 2. Engine reality

```bash
node scripts/engine_reality_audit.mjs
```

**Pass:** אפס `no_path`. ספירה: `real_probe`, `agent_required`, `alias`, `special`.

### 3. UI audit

```bash
node scripts/weissman-ui-audit.mjs
```

**Pass:** כל עמודי Command Center — evidence, refresh, export, search. **94/94**.

### 4. Rust

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace
```

### 5. Frontend

```bash
cd frontend && npm ci && npm run build
```

### 6. Staging QA (one command)

```bash
chmod +x scripts/staging-qa.sh
./scripts/staging-qa.sh
./scripts/staging-qa.sh --live http://localhost
```

ספר **19** — Paddle, SMTP, LLM, OAST, Agent, Docker staging.

---

## אימות אבטחה

| בדיקה | Pass |
|-------|------|
| JWT חלש → refuse boot | blocked |
| secure cookies + HTTPS | Secure flag |
| metrics ללא token → 401 | 401 |
| destructive ללא header → 403 | 403 |
| admin password rotated | changed |
| billing strict | quota error ללא מנוי |

ספר **05**.

---

## Smoke tests

### Auth

- [ ] `POST /api/login` ב-`/command-center/login`
- [ ] `GET /api/auth/me` admin
- [ ] MFA setup + verify
- [ ] logout
- [ ] viewer לא מריץ scans
- [ ] operator מריץ

### Client / billing

- [ ] client + domains
- [ ] Billing usage
- [ ] max_clients (strict)

### Scan pipeline

- [ ] `POST /api/command-center/scan` → job
- [ ] worker claim < 60s
- [ ] findings ב-UI
- [ ] `completed`

מנועים: `real_probe` + `agent_required` (empty לפני agent, findings אחרי).

### Agent (אם ב-scope)

- [ ] `/install/agent.sh`
- [ ] online
- [ ] host finding

### Reports

- [ ] CSV
- [ ] PDF

### Integrations / SSO (אם נמכר)

- [ ] CI webhook
- [ ] alert webhook
- [ ] SSO login

---

## תשתית

```bash
curl -sf https://staging.example.com/api/health
curl -sf https://staging.example.com/command-center/
docker compose ps
```

- [ ] Postgres backups tested
- [ ] Redis (multi-replica)
- [ ] TLS valid
- [ ] legal pages (`/terms.html`, `/privacy.html`, `/dpa.html`)

Monitoring:

```bash
docker compose --profile monitoring up -d
```

---

## Baseline ביצועים

| מetric | יעד staging |
|--------|-------------|
| health p95 | < 200 ms |
| claim latency | < 30 s |
| recon engine | < 5 min |
| concurrent light | = `WEISSMAN_WORKER_LIGHT_CONCURRENCY` |

---

## מסמך sign-off

```
לקוח: _______________
URL: _______________
תאריך: _______________

אוטומטי:
  [ ] verify_engine_wiring.mjs — 0 gaps
  [ ] engine_reality_audit.mjs — 0 no_path
  [ ] weissman-ui-audit.mjs — pass
  [ ] cargo test — pass
  [ ] frontend build — pass

ידני:
  [ ] login + MFA
  [ ] client + scan + findings
  [ ] agent (אם scope)
  [ ] PDF
  [ ] security guards

אישור: _______________
```

---

## Regression אחרי שדרוג

1. rebuild
2. סקריפטים 1–3
3. health + smoke scan
4. migration logs

---

## ספרים קשורים

- [00-sales-delivery-readiness](00-sales-delivery-readiness.md)
- [05-production-security](05-production-security.md)
- [09-client-onboarding](09-client-onboarding.md)
- [10-scans-engines-jobs](10-scans-engines-jobs.md)
- [16-operations-monitoring](16-operations-monitoring.md)
- [17-troubleshooting](17-troubleshooting.md)
