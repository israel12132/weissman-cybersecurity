# 07 — אימות, RBAC ו-MFA

## מטרה

הגדרת גישה אנושית ל-Weissman: login, היררכיית תפקידים, MFA, ניהול sessions, וציפיות audit לצוות SOC.

---

## דרישות מקדימות

- פלטפורמה פרוסה (ספרים 02–04)
- `WEISSMAN_JWT_SECRET` (≥ 32 ב-production)
- Redis מומלץ ל-lockout
- HTTPS + `WEISSMAN_COOKIE_SECURE=1`

---

## סקירת אימות

JWT קצר-טווח + refresh cookies (HttpOnly, opaque).

| Endpoint | Method | תפקיד |
|----------|--------|--------|
| `/api/login` | POST | Login ראשי — email + password |
| `/api/logout` | POST | סיום session |
| `/api/auth/me` | GET | פרופיל משתמש |
| `/api/auth/refresh` | POST | רענון token |
| `/api/auth/sse-ticket` | GET | כרטיס ל-SSE |

**חשוב:** Login הוא **`POST /api/login`**, לא `/api/auth/login`.

Bootstrap:

```bash
WEISSMAN_ADMIN_EMAIL=admin@yourcompany.com
WEISSMAN_ADMIN_PASSWORD=<מ-env>
```

---

## היררכיית RBAC

ב-`fingerprint_engine/src/rbac.rs`:

```
viewer < analyst < operator < admin < ceo
```

| תפקיד | דירוג | הרשאות אופייניות |
|--------|-------|------------------|
| `viewer` | 1 | קריאה, dashboards |
| `analyst` | 2 | triage, הערות, export |
| `operator` | 3 | סריקות, clients, integrations |
| `admin` | 4 | משתמשים, billing, SSO |
| `ceo` | 5 | CEO Mission Control, council |

**Superadmin** עוקף את כל הבדיקות.

תפקיד **`agent`** — ל-agents בלבד, לא לבני אדם.

רק **CEO או superadmin** יכולים להקצות `ceo`.

### Self-service (כל משתמש מאומת)

`/api/auth/mfa/*`, `/api/auth/change-password`, `/api/account`, `/api/me`.

---

## שלב אחר שלב: login admin ראשון

### 1. Command Center

`https://your-domain.example/command-center/login`

### 2. אימות

```bash
curl -c cookies.txt -X POST https://your-domain.example/api/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@yourcompany.com","password":"YOUR_PASSWORD"}'
```

### 3. החלפת סיסמה

Account → Change Password, או `POST /api/auth/change-password`.

### 4. יצירת משתמשים

Admin → Users. הקצו תפקיד מינימלי:

- אנליסט SOC → `analyst`
- מפעיל סריקות → `operator`
- מנהל פלטפורמה → `admin`

---

## MFA (TOTP)

| Endpoint | תפקיד |
|----------|--------|
| `POST /api/auth/mfa/setup` | QR + secret |
| `POST /api/auth/mfa/enable` | הפעלה |
| `POST /api/auth/mfa/verify` | שלב שני ב-login |
| `POST /api/auth/mfa/disable` | ביטול |
| `GET /api/auth/mfa/status` | סטטוס |

Lockout כולל `/api/login` ו`/api/auth/mfa/verify` (Redis).

**נוהל admin חדש:**

1. Login ללא MFA
2. Account → Enable MFA
3. סריקת QR
4. שמירת recovery codes
5. בדיקת logout/login עם MFA

---

## אבטחת session

Production (`security_startup.rs`):

- `WEISSMAN_ENV=production`
- `WEISSMAN_COOKIE_SECURE=1`
- `?access_token=` נדחה

TTL: `WEISSMAN_ACCESS_TOKEN_MINUTES` (ברירת מחדל 15), `WEISSMAN_REFRESH_TOKEN_DAYS` (30).

---

## SSO

- `GET /api/auth/oidc/begin`
- `GET /api/auth/saml/begin`
- `POST /api/auth/saml/acs`

ספר **14**.

---

## Audit

Login, שינויי תפקיד, פעולות הרסניות → `audit_logs`. `WEISSMAN_LOG_FORMAT=json` ל-SIEM.

---

## אימות

```bash
curl -sf -c /tmp/wc -X POST https://localhost/api/login \
  -H 'Content-Type: application/json' -d '{"email":"...","password":"..."}'
curl -sf -b /tmp/wc https://localhost/api/auth/me | jq .role
curl -sf -b /tmp/wc https://localhost/api/auth/mfa/status
```

בדקו גבולות תפקיד לכל persona לפני go-live.

---

## פתרון תקלות

| תסמין | תיקון |
|--------|-------|
| 401 על API | JWT פג תוקף — refresh/login |
| 403 role | תפקיד נמוך; Users admin |
| חשבון ננעל | lockout Redis — המתנה |
| MFA loop | סנכרון שעון |

ראו [17-troubleshooting](17-troubleshooting.md).

---

## ספרים קשורים

- [05-production-security](05-production-security.md)
- [08-billing-multitenancy](08-billing-multitenancy.md)
- [09-client-onboarding](09-client-onboarding.md)
- [14-sso-identity](14-sso-identity.md)
