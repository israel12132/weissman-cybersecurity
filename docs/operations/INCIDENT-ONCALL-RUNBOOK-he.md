# Runbook — תגובה לאירועים ו-On-Call

**Weissman Cybersecurity Ltd.** · גרסה 1.0 · 2026-06

---

## 1. מטרה

נהל תגובה עקבית ל-incidents production: זמינות, אבטחה, נתוני לקוח.

---

## 2. חומרות (Severity)

| רמה | דוגמה | יעד תגובה ראשונית |
|-----|--------|-------------------|
| **SEV-1** | Platform down, דליפת tenant, RCE | 15 דקות |
| **SEV-2** | Scans stuck, billing broken, auth partial | 1 שעה |
| **SEV-3** | מנוע בודד, UI bug, degradation | 4 שעות business |
| **SEV-4** | שאלה, docs, feature request | 24 שעות |

Enterprise SLA: ראו `SLA_AND_STATUS.md` + Order Form.

---

## 3. אנשי קשר (מלאו ב-production)

| תפקיד | אימייל | טלפון |
|--------|--------|-------|
| On-call primary | oncall@weissman.io | __________ |
| Security lead | security@weissman.io | __________ |
| CEO escalation | __________ | __________ |

PagerDuty / Opsgenie webhook: `WEISSMAN_ONCALL_WEBHOOK_URL` (אופציונלי ב-`.env`).

---

## 4. ז flow — SEV-1 / SEV-2

1. **Detect** — `/api/health`, `/command-center/status`, Prometheus alerts, לקוח מדווח.
2. **Triage** — `docker compose ps`, logs: `backend`, `worker`, `postgres`, `redis`.
3. **Communicate** — עדכון `/status` + email ללקוחות Enterprise תוך 30 דקות (SEV-1).
4. **Mitigate** — rollback image, scale worker, disable destructive paths.
5. **Resolve** — verify `./scripts/staging-qa.sh --live`.
6. **Post-mortem** — תוך 5 business days: timeline, root cause, action items.

---

## 5. פקודות מהירות

```bash
# Health
curl -sf https://<host>/api/health | jq .

# Stack
docker compose ps
docker compose logs -f --tail=200 backend worker

# DB connectivity
docker compose exec postgres pg_isready -U postgres

# Redis
docker compose exec redis redis-cli ping
```

---

## 6. אבטחה — suspected breach

1. **אל** תמחק logs.
2. Rotate: `WEISSMAN_JWT_SECRET`, admin passwords, `PADDLE_WEBHOOK_SECRET`, agent tokens.
3. `security@weissman.io` + legal.
4. Notify customers per DPA breach clause if PII affected.

---

## 7. קישורים

- `SLA_AND_STATUS.md`
- `SECURITY_AND_COMPLIANCE.md`
- `docs/manuals/he/17-troubleshooting.md`
- `deploy/public/security-policy.html`
