# 05 — הקשחת Production

## מטרה

הגדרת Weissman לאבטחת **production**: startup guards שמסרבים קונפיגורציה חלשה, sessions ב-HTTPS בלבד, metrics מוגנים, billing, ובקרה אנושית על פעולות הרסניות.

---

## דרישות מקדימות

- שיטת פריסה נבחרה (ספרים 02–04)
- תעודת TLS + reverse proxy
- סודות מ-`openssl rand -base64 48`
- גישה ל-`SECURITY_AND_COMPLIANCE.md`

---

## מתג production מרכזי

```bash
WEISSMAN_ENV=production
```

על **server וworker**. מפעיל guards ב-`fingerprint_engine/src/security_startup.rs`. בלי זה — מצב dev מתיר גם עם סודות אמיתיים.

### מה ה-guards בודקים

| בדיקה | כשל |
|-------|------|
| `WEISSMAN_JWT_SECRET` חסר או < 32 | Refuse boot |
| ערכי JWT חלשים (`changeme`, placeholders) | Refuse boot |
| fragments חלשים ב-DB URL | Refuse boot |
| `WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD=1` | Refuse boot |
| `WEISSMAN_SAML_INSECURE_SKIP_VERIFY=1` | Refuse boot |
| `WEISSMAN_COOKIE_SECURE` לא מופעל (server) | Refuse boot |
| `WEISSMAN_MIGRATE_URL` חסר (server) | Refuse boot |
| `WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET` חסר | Refuse boot |
| `WEISSMAN_METRICS_TOKEN` חסר | Refuse boot |
| JWT ב-`?access_token=` | נדחה ב-runtime |

---

## רשימת הקשחה

### 1. סיבוב סודות

```bash
openssl rand -base64 48   # WEISSMAN_JWT_SECRET
openssl rand -base64 48   # WEISSMAN_METRICS_TOKEN
openssl rand -base64 48   # WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET
```

החליפו סיסמת admin אחרי login ראשון.

### 2. Session cookies מאובטחים

```bash
WEISSMAN_COOKIE_SECURE=1
WEISSMAN_PUBLIC_BASE_URL=https://your-domain.example
```

Login: **`POST /api/login`** (לא `/api/auth/login`).

### 3. אישור פעולות הרסניות

```bash
WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET=<random>
```

Header נדרש:

```
X-Weissman-Destructive-Confirm: <ערך מדויק>
```

מימוש: `security_hardening.rs`. ב-production — חסר secret חוסם boot; חסר header → 403.

### 4. הגנה על metrics

```bash
WEISSMAN_METRICS_TOKEN=<token>
```

`GET /api/metrics` דורש `Authorization: Bearer <token>`.

### 5. Billing strict

ברירת מחדל: `WEISSMAN_BILLING_STRICT=1` עם `WEISSMAN_ENV=production`.

Self-hosted unlimited: `WEISSMAN_BILLING_STRICT=0` **רק עם חוזה כתוב**.

נתיבי scan קוראים ל-`gate_scan_enqueue`.

### 6. רשת ו-TLS

- חשיפה ציבורית: 443 בלבד
- Postgres/Redis לא מהאינטרנט
- `WEISSMAN_TRUST_PROXY_HEADERS=1` רק מאחורי proxy מהימן
- לעולם לא `WEISSMAN_ALLOW_INSECURE_TLS=1` ב-production

### 7. Redis

```bash
REDIS_URL=redis://host:6379/0
```

נדרש ל-rate limits, lockout (`/api/login`, `/api/auth/mfa/verify`), registry של agents.

### 8. SAML / OIDC

- `WEISSMAN_XMLSEC1_BINARY` ל-SAML
- לעולם לא `WEISSMAN_SAML_INSECURE_SKIP_VERIFY` ב-production
- Redirect URIs ל-`WEISSMAN_PUBLIC_BASE_URL`

ספר **14**.

### 9. Self-serve signup (SaaS)

```bash
WEISSMAN_SELF_SERVE_SIGNUP=true
WEISSMAN_ALLOW_SELF_SERVE_IN_PRODUCTION=true
```

דורש SMTP. לעולם לא `WEISSMAN_SIGNUP_RETURN_LINK=1` ב-production.

---

## Headers ודפים משפטיים

`deploy/nginx-security-headers.inc`. דפים מ-`deploy/public/` (terms, privacy, DPA).

---

## אימות

```bash
# JWT חלש → startup error (staging בלבד)
WEISSMAN_ENV=production WEISSMAN_JWT_SECRET=changeme ./target/release/weissman-server

curl -sf https://your-domain.example/api/health
curl -s -o /dev/null -w "%{http_code}" https://your-domain.example/api/metrics
# 401 ללא Bearer
```

---

## ספרים קשורים

- [06-environment-configuration](06-environment-configuration.md)
- [07-authentication-rbac-mfa](07-authentication-rbac-mfa.md)
- [08-billing-multitenancy](08-billing-multitenancy.md)
- [14-sso-identity](14-sso-identity.md)
- [16-operations-monitoring](16-operations-monitoring.md)
- [18-qa-verification](18-qa-verification.md)
