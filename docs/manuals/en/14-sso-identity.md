# 14 — SSO & Identity

## Purpose

Integrate Weissman with enterprise identity providers via **OIDC** and **SAML 2.0**, enabling centralized authentication, JIT provisioning, and SSO dashboard management.

---

## Prerequisites

- Admin role for SSO configuration
- `WEISSMAN_PUBLIC_BASE_URL` set to canonical HTTPS origin
- IdP admin access (Azure AD, Okta, Google Workspace, etc.)
- Production: `WEISSMAN_XMLSEC1_BINARY` for SAML crypto verification
- `WEISSMAN_ENV=production` with `WEISSMAN_COOKIE_SECURE=1`

---

## Supported protocols

| Protocol | Begin URL | Callback |
|----------|-----------|----------|
| OIDC | `GET /api/auth/oidc/begin` | IdP redirect to configured callback |
| SAML 2.0 | `GET /api/auth/saml/begin` | `POST /api/auth/saml/acs` |

SP metadata: `{WEISSMAN_PUBLIC_BASE_URL}/saml/metadata`

Optional issuer override: `WEISSMAN_SAML_SP_ISSUER`

---

## Step-by-step: OIDC (e.g., Azure AD)

### 1. Register application in IdP

- Application type: Web
- Redirect URI: `https://your-domain.example/api/auth/oidc/callback`
- Grant types: authorization code
- Collect: Client ID, Client Secret, Issuer URL

### 2. Configure in Command Center

Admin → **SSO Dashboard** → Add OIDC Provider

| Field | Value |
|-------|-------|
| Issuer | `https://login.microsoftonline.com/{tenant}/v2.0` |
| Client ID | From IdP |
| Client Secret | From IdP (stored encrypted) |
| Scopes | `openid email profile` |
| Default role | `viewer` (adjust per group mapping) |

Backend: `fingerprint_engine/src/oidc_auth.rs`

### 3. Map groups to roles

Configure IdP group claims → Weissman roles:

- `Security-Analysts` → `analyst`
- `Scan-Operators` → `operator`
- `Platform-Admins` → `admin`

Unmapped users receive default role (minimum `viewer`).

### 4. Test login

1. Log out of Command Center
2. Click **Sign in with SSO**
3. Complete IdP authentication
4. Verify `GET /api/auth/me` returns expected role

---

## Step-by-step: SAML 2.0

### 1. IdP configuration

- ACS URL: `https://your-domain.example/api/auth/saml/acs`
- Entity ID: `{WEISSMAN_PUBLIC_BASE_URL}/saml/metadata`
- NameID format: emailAddress
- Sign assertions: required

### 2. Server requirements

```bash
WEISSMAN_XMLSEC1_BINARY=/usr/bin/xmlsec1
WEISSMAN_PUBLIC_BASE_URL=https://your-domain.example
```

**Never** set `WEISSMAN_SAML_INSECURE_SKIP_VERIFY=1` in production — startup guard refuses boot.

Install xmlsec1:

```bash
sudo apt install xmlsec1
```

### 3. Upload IdP metadata

SSO Dashboard → Add SAML Provider → paste IdP metadata XML or configure manually (SSO URL, certificate).

Backend: `fingerprint_engine/src/saml_auth.rs`

### 4. Test assertion flow

Initiate from `GET /api/auth/saml/begin`. Confirm session cookie set and audit log records SSO login.

---

## SSO management API

Operator+ endpoints in `fingerprint_engine/src/sso_management.rs`:

- List/configure/disable SSO providers
- Test connectivity
- View last sync status

Destructive SSO changes may require admin role.

---

## Hybrid auth model

Local `POST /api/login` remains available for break-glass admin accounts. Best practice:

- Disable local passwords for standard users after SSO cutover
- Retain one MFA-protected local admin for IdP outage
- Document break-glass procedure in runbook

MFA endpoints (`/api/auth/mfa/*`) apply to local accounts. IdP MFA is enforced at IdP layer for SSO users.

---

## Multi-tenant SSO

Each tenant may configure independent IdP connections. Tenant slug determines SSO config scope. Enterprise deployments isolate IdP per customer tenant.

---

## Verification

```bash
# Metadata endpoint
curl -sf https://your-domain.example/saml/metadata | head -20

# OIDC discovery (from server logs or admin test button)
# SSO Dashboard → Test Connection → expect success

# Post-login profile
curl -sf -b sso_cookies.txt https://your-domain.example/api/auth/me | jq '{email, role, sso_provider}'

# Production guard check
grep WEISSMAN_SAML_INSECURE /etc/weissman/weissman.env
# Must be unset or 0
```

Checklist:

- [ ] SSO login completes without error
- [ ] Role mapping correct for test users
- [ ] Logout clears session; re-login works
- [ ] Audit log shows SSO authentication event
- [ ] Break-glass local admin still functional

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Redirect URI mismatch | Align IdP callback with `WEISSMAN_PUBLIC_BASE_URL` |
| SAML signature fail | Install xmlsec1; verify IdP cert not expired |
| User gets viewer only | Fix group claim mapping |
| SSO button 503 | Provider not configured for tenant |
| Cookie not set | `WEISSMAN_COOKIE_SECURE=1` requires HTTPS |

See [17-troubleshooting](17-troubleshooting.md).

---

## Related manuals

- [05-production-security](05-production-security.md)
- [06-environment-configuration](06-environment-configuration.md)
- [07-authentication-rbac-mfa](07-authentication-rbac-mfa.md)
