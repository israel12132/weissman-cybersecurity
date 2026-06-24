# 08 — Billing ו-Multi-Tenancy

## מטרה

הגדרת בידוד tenants, מנוי Paddle, מכסות סריקה, ו-gates שמגנים על מגבלות מסחריות ב-production.

---

## דרישות מקדימות

- PostgreSQL עם migrations של billing
- חשבון Paddle (sandbox / production)
- `WEISSMAN_ENV=production` → strict billing ברירת מחדל
- תפקיד admin

---

## מודל multi-tenancy

בידוד לפי **tenant**:

- RLS על טבלאות app (`weissman_app`)
- מישור auth (`weissman_auth`, BYPASSRLS ל-login)
- לכל tenant: users, clients, findings, counters, מנוי Paddle

Tenant `default` — workspace bootstrap.

---

## ארכיטקטורת billing

`fingerprint_engine/src/billing/mod.rs`:

| רכיב | תפקיד |
|------|--------|
| `tenant_subscriptions` | מצב Paddle |
| `billing_plans` | plans, max clients, quota חודשית |
| `tenant_usage_counters` | ספירת סריקות |
| Paddle webhooks | lifecycle |
| `gate_scan_enqueue` | חסימת enqueue |

### Strict billing

`WEISSMAN_BILLING_STRICT`:

- **`1`:** יצירת client + סריקות דורשות מנוי פעיל
- **`0`:** gates מושבתים (self-hosted unlimited בחוזה)

**ברירות מחדל:**

1. ערך env מ显式
2. `WEISSMAN_ENV=production` → strict **on**
3. `PADDLE_API_KEY` מוגדר → strict **on**
4. אחרת **off** (dev)

---

## שלב אחר שלב: Paddle

### 1. משתני env

```bash
PADDLE_API_KEY=pdl_live_apikey_...
PADDLE_ENVIRONMENT=production
PADDLE_WEBHOOK_SECRET=pdl_ntfset_...
WEISSMAN_BILLING_STRICT=1
WEISSMAN_PUBLIC_BASE_URL=https://your-domain.example
```

### 2. Webhook

הגדירו URL ב-Paddle. אימות חתימה עם `PADDLE_WEBHOOK_SECRET`.

### 3. מיפוי price IDs

Plans ב-DB עם `pri_*`. קטלוג לקוח-ספציפי — ספר **00**.

### 4. Pilot / evaluation

```bash
WEISSMAN_BILLING_STRICT=0
```

תיעוד ב-SOW. הפעילו strict לפני billing production.

---

## נקודות enforcement

| פעולה | Gate |
|--------|------|
| סריקה | `gate_scan_enqueue` |
| סריקות מתוזמנות | `gate_scan_enqueue_n` |
| יצירת client | `enforce_client_create` |
| run-all | בדיקת quota |

API מחזיר שגיאת subscription/quota. UI Billing מציג usage.

---

## UI Billing

`/command-center/billing` (admin):

- plan + usage
- Paddle checkout
- סטטוס מנוי

---

## Self-serve signup (SaaS)

`deploy/public/signup.html` → `POST /api/auth/signup`:

```bash
WEISSMAN_SELF_SERVE_SIGNUP=true
WEISSMAN_ALLOW_SELF_SERVE_IN_PRODUCTION=true
WEISSMAN_SMTP_ENABLED=true
```

---

## אימות

```bash
curl -sf -b cookies.txt https://localhost/api/billing/status
# סריקה ללא מנוי (strict) → שגיאת quota
curl -X POST -b cookies.txt https://localhost/api/command-center/scan \
  -H 'Content-Type: application/json' \
  -d '{"engine":"dns_recon","client_id":1,"target":"example.com"}'
```

---

## פתרון תקלות

| תסמין | תיקון |
|--------|-------|
| Subscription not provisioned | webhook; replay |
| סריקות חסומות | quota חודשית; שדרוג plan |
| Checkout 503 | `PADDLE_API_KEY` |
| Strict ב-dev | `WEISSMAN_BILLING_STRICT=0` |

ראו [17-troubleshooting](17-troubleshooting.md).

---

## ספרים קשורים

- [05-production-security](05-production-security.md)
- [06-environment-configuration](06-environment-configuration.md)
- [07-authentication-rbac-mfa](07-authentication-rbac-mfa.md)
- [09-client-onboarding](09-client-onboarding.md)
- [10-scans-engines-jobs](10-scans-engines-jobs.md)
