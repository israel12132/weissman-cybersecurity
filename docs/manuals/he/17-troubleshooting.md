# 17 — Troubleshooting (פתרון תקלות)

## מטרה

אבחון ותיקון תקלות נפוצות: התקנה, auth, סריקות, billing, agents, integrations.

---

## דרישות מקדימות

- shell / kubectl
- גישה ל-logs
- credentials operator
- חבילת ספרים + `/docs/operations.md`

---

## טבלת אבחון מהיר

| תסמין | בדיקה ראשונה |
|--------|-------------|
| 502 | backend health; PORT |
| login נכשל | `POST /api/login`; lockout |
| jobs תקועים | worker |
| 403 scans | billing / RBAC |
| agent offline | token; firewall |
| SSO | `WEISSMAN_PUBLIC_BASE_URL` |
| boot נכשל | `security_startup` logs |

---

## התקנה / startup

### Backend יוצא מיד

`fingerprint_engine/src/security_startup.rs`:

```bash
docker compose logs backend --tail 50
journalctl -u weissman-server -n 50
```

| שגיאה | תיקון |
|-------|-------|
| JWT < 32 | secret חזק |
| weak/default JWT | החלפת placeholder |
| COOKIE_SECURE | HTTPS + `=1` |
| MIGRATE_URL | superuser URL |
| DESTRUCTIVE secret | generate |
| `CEO genesis vault has no dedicated key` / אין מפתח vault | `WEISSMAN_VAULT_KEY` = 64 hex (`openssl rand -hex 32`). `./start_weissman_live.sh` מייצר אותו; חייב להגיע לקונטיינר דרך `environment:` |
| DB password weak | rotate Postgres |

### Compose exit 15

`.env` — quote ערכים עם `:`. מינימום:

```bash
WEISSMAN_JWT_SECRET=...
WEISSMAN_ADMIN_PASSWORD=...
```

### 502

```bash
deploy/fix-weissman-502.sh
curl -sf http://127.0.0.1:8000/api/health
```

---

## Authentication

### 401 login

1. **`POST /api/login`**
2. email/password
3. lockout Redis
4. MFA: `/api/auth/mfa/verify`

### session קצר

`WEISSMAN_ACCESS_TOKEN_MINUTES` (max 240).

### 403 role

`GET /api/auth/me` → hierarchy: viewer < analyst < operator < admin < ceo.

---

## Scans / jobs

### queued

```bash
docker compose ps worker
systemctl status weissman-worker
```

`DATABASE_URL` זהה ל-server.

### billing error

`gate_scan_enqueue` — strict, Paddle, quota. `WEISSMAN_BILLING_STRICT=0` בחוזה בלבד.

### scope error

עדכון domains ב-client.

### agent empty

תקין — ספר 12.

---

## Agent

### 404 install

`bash scripts/package_agent_binaries.sh`. Routes: `/install/agent.sh`, `/install/agent.ps1`.

### SHA mismatch

rebuild + republish.

### offline

HTTPS/WSS; token revoked.

---

## SSO

redirect URI = `WEISSMAN_PUBLIC_BASE_URL`. SAML: xmlsec1; לא `INSECURE_SKIP` ב-production.

---

## Webhooks

CI: URL, HMAC, `client_id`. Alerts: `WEISSMAN_ALERT_WEBHOOK_URL`, conditions.

---

## DB / Redis

pool: `WEISSMAN_APP_POOL_MAX`. migrations: backend logs. Redis down — rate limits degraded.

---

## Destructive

```
X-Weissman-Destructive-Confirm: <WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET>
```

---

## אימות אחרי תיקון

```bash
curl -sf https://your-domain.example/api/health
# login + smoke scan; worker claim < 60s
```

QA subset — ספר 18.

---

## Escalation

1. logs (server + worker, שעה)
2. הודעת שגיאה + timestamp
3. `/SLA_AND_STATUS.md`
4. `audit_logs` ל-incidents

---

## ספרים קשורים

- [02-installation-docker](02-installation-docker.md)
- [05-production-security](05-production-security.md)
- [07-authentication-rbac-mfa](07-authentication-rbac-mfa.md)
- [08-billing-multitenancy](08-billing-multitenancy.md)
- [10-scans-engines-jobs](10-scans-engines-jobs.md)
- [12-endpoint-agent](12-endpoint-agent.md)
- [16-operations-monitoring](16-operations-monitoring.md)
- [18-qa-verification](18-qa-verification.md)
