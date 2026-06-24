# 09 — Onboarding לקוח

## מטרה

קליטת ארגוני לקוח ל-Weissman להערכות אבטחה **מורשות**. כולל דרישות משפטיות, scope, סריקה ראשונה, ו-nohut חירום.

**קריטי:** onboard רק עם **הרשאה כתובה מפורשת** לבדיקות אבטחה.

---

## דרישות מקדימות

- תפקיד operator ויותר
- מנוי פעיל (כש-`WEISSMAN_BILLING_STRICT=1`)
- MSA/SOW עם scope מורשה
- QA (ספר 18)
- אנשי קשר לחירום

---

## רשימת pre-onboarding

### משפטי

- [ ] MSA / SOW חתום
- [ ] מכתב הרשאה
- [ ] scope (domains, IPs, apps)
- [ ] exclusions
- [ ] חלון בדיקות
- [ ] POCs
- [ ] escalation

### טכני

- [ ] IT מודע ללוח זמנים
- [ ] Firewall/WAF
- [ ] ניטור (הפחת false positives)
- [ ] credentials לסריקות מאומתות
- [ ] תכנון agent (אם נמכר)

### פלטפורמה

- [ ] `GET /api/health` OK
- [ ] worker מעבד jobs
- [ ] גיבויים עדכניים
- [ ] alerting (ספר 15)

---

## שלב אחר שלב

### 1. Login

`/command-center/login` — `POST /api/login`. MFA אם מופעל. תפקיד **operator+**.

### 2. יצירת client

**Clients** → **Add Client**

| שדה | הנחיה |
|------|--------|
| שם משפטי | ישות בחוזה |
| Primary domain | דומיין ראשי |
| Authorized domains | כל FQDNs במ-scope |
| IP ranges | CIDR |
| Exclusions | מחוץ scope |
| ROE | Rules of Engagement |

Gate: `enforce_client_create` — מנוי + `max_clients`.

### 3. ROE

תיעוד:

- סוגי סריקות מותרים
- חלונות זמן
- rate limits
- איסורים (DoS ו)
- טלפון stop חירום

יישור עם `/ONBOARDING_RUNBOOK.md`.

### 4. לוח זמנים (אופציוני)

**Schedules** — cron + engine + client. `gate_scan_enqueue_n` לבדיקת quota.

### 5. סריקה ראשונה

התחילו ב-reconnaissance קל:

1. Engine hub (Domain Discovery, DNS Recon)
2. בחרו client
3. ו target ב-scope
4. **Run**

API: `POST /api/command-center/scan` עם `{ engine, client_id, target }`.

ניטור ב-**Jobs**.

### 6. סקירת findings

**Findings** — triage לפי חומרה. findings מחוץ scope = עצירה ותיקון.

### 7. Agent (אם ב-scope)

~45 מנועי `agent_required`:

1. Token ב-**Agent Management**
2. `GET /install/agent.sh` / `GET /install/agent.ps1`
3. agent online לפני מנועים gated

ספר **12**.

### 8. דוח ראשון

PDF/CSV. כולל scope ו-ROE.

---

## נוהלי חירום

### עצירת סריקה מיידית

1. ביטול jobs ב-**Jobs**
2. השבת schedules
3. הודעה ל-POC
4. תיעוד ב-audit

### הפרת scope

1. **עצור כל הסריקות**
2. POC + legal
3. audit logs
4. תיקון scope לפני המשך

### תקלת פלטפורמה

`/SLA_AND_STATUS.md`. שמירת logs:

```bash
journalctl -u weissman-server --since "1 hour ago" > incident-server.log
journalctl -u weissman-worker --since "1 hour ago" > incident-worker.log
```

---

## אימות

- [ ] Client עם domains נכונים
- [ ] סריקת בדיקה הושלמה
- [ ] אין findings על exclusions
- [ ] Agent online (אם רלוונטי)
- [ ] PDF נ reviewed
- [ ] חתימת QA (ספר 18)

---

## ספרים קשורים

- [07-authentication-rbac-mfa](07-authentication-rbac-mfa.md)
- [08-billing-multitenancy](08-billing-multitenancy.md)
- [10-scans-engines-jobs](10-scans-engines-jobs.md)
- [11-findings-reports](11-findings-reports.md)
- [12-endpoint-agent](12-endpoint-agent.md)
- `/ONBOARDING_RUNBOOK.md`
