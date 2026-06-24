# 14 — SSO & Identity

## מטרה

אינטגרציה עם IdP ארגוני דרך **OIDC** ו-**SAML 2.0** — אימות מרכזי, JIT provisioning, SSO dashboard.

---

## דרישות מקדימות

- admin ל-SSO
- `WEISSMAN_PUBLIC_BASE_URL` HTTPS
- גישת IdP admin
- production: `WEISSMAN_XMLSEC1_BINARY`
- `WEISSMAN_COOKIE_SECURE=1`

---

## פרוטוקולים

| פרוטוקול | Begin | Callback |
|----------|-------|----------|
| OIDC | `GET /api/auth/oidc/begin` | IdP redirect |
| SAML | `GET /api/auth/saml/begin` | `POST /api/auth/saml/acs` |

Metadata: `{WEISSMAN_PUBLIC_BASE_URL}/saml/metadata`

`WEISSMAN_SAML_SP_ISSUER` — override אופציוני.

---

## OIDC (Azure AD) — שלבים

### 1. רישום ב-IdP

- Redirect: `https://your-domain.example/api/auth/oidc/callback`
- Authorization code
- Client ID, Secret, Issuer

### 2. SSO Dashboard

| שדה | ערך |
|------|-----|
| Issuer | `https://login.microsoftonline.com/{tenant}/v2.0` |
| Client ID / Secret | מ-IdP |
| Scopes | `openid email profile` |
| Default role | `viewer` |

`oidc_auth.rs`

### 3. Group mapping

- `Security-Analysts` → `analyst`
- `Scan-Operators` → `operator`
- `Platform-Admins` → `admin`

### 4. בדיקה

Sign in with SSO → `GET /api/auth/me` — role נכון.

---

## SAML — שלבים

### 1. IdP

- ACS: `https://your-domain.example/api/auth/saml/acs`
- Entity ID: metadata URL
- NameID: emailAddress

### 2. שרת

```bash
WEISSMAN_XMLSEC1_BINARY=/usr/bin/xmlsec1
WEISSMAN_PUBLIC_BASE_URL=https://your-domain.example
```

**לעולם לא** `WEISSMAN_SAML_INSECURE_SKIP_VERIFY=1`.

```bash
sudo apt install xmlsec1
```

### 3. Metadata IdP

SSO Dashboard → SAML → paste XML.

`saml_auth.rs`

### 4. בדיקה

`saml/begin` → session cookie + audit.

---

## SSO management API

`sso_management.rs` — operator+: list/configure/test.

---

## Hybrid auth

`POST /api/login` ל-break-glass. נוהל:

- SSO לרוב המשתמשים
- admin מקומי אחד + MFA ל-outage IdP
- נוהל ב-runbook

MFA מקומי: `/api/auth/mfa/*`. SSO MFA — ב-IdP.

---

## Multi-tenant SSO

IdP נפרד לכל tenant (enterprise).

---

## אימות

```bash
curl -sf https://your-domain.example/saml/metadata | head -20
curl -sf -b sso_cookies.txt https://your-domain.example/api/auth/me | jq '{email, role}'
grep WEISSMAN_SAML_INSECURE /etc/weissman/weissman.env
# חייב unset
```

- [ ] SSO login OK
- [ ] role mapping
- [ ] logout/login
- [ ] audit event
- [ ] break-glass admin

---

## פתרון תקלות

| תסמין | תיקון |
|--------|-------|
| redirect mismatch | `WEISSMAN_PUBLIC_BASE_URL` |
| SAML signature | xmlsec1; cert |
| viewer בלבד | group mapping |
| SSO 503 | provider לא מוגדר |
| cookie | HTTPS + SECURE |

ראו [17-troubleshooting](17-troubleshooting.md).

---

## ספרים קשורים

- [05-production-security](05-production-security.md)
- [06-environment-configuration](06-environment-configuration.md)
- [07-authentication-rbac-mfa](07-authentication-rbac-mfa.md)
