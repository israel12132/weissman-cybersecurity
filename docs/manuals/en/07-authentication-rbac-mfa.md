# 07 — Authentication, RBAC & MFA

## Purpose

Configure human access to Weissman: login flows, role hierarchy, multi-factor authentication, session management, and audit expectations for SOC and admin teams.

---

## Prerequisites

- Platform deployed and healthy (manual 02–04)
- `WEISSMAN_JWT_SECRET` configured (≥ 32 characters in production)
- Redis recommended for login lockout and rate limits
- HTTPS with `WEISSMAN_COOKIE_SECURE=1` in production

---

## Authentication overview

Weissman uses **JWT access tokens** (short-lived) plus **HttpOnly refresh cookies** (opaque, rotatable).

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/login` | POST | Primary login — email + password |
| `/api/logout` | POST | End session |
| `/api/auth/me` | GET | Current user profile |
| `/api/auth/refresh` | POST | Rotate access token from refresh cookie |
| `/api/auth/sse-ticket` | GET | Short-lived ticket for SSE streams |

**Important:** Login is **`POST /api/login`**, not `/api/auth/login`. Legacy docs mentioning `/api/auth/login` refer to probe targets, not the operator login path.

Default bootstrap credentials (change immediately):

```bash
WEISSMAN_ADMIN_EMAIL=admin@yourcompany.com
WEISSMAN_ADMIN_PASSWORD=<from env>
```

---

## Role hierarchy (RBAC)

Canonical roles in `fingerprint_engine/src/rbac.rs`:

```
viewer < analyst < operator < admin < ceo
```

| Role | Rank | Typical permissions |
|------|------|-------------------|
| `viewer` | 1 | Read dashboards, findings, reports |
| `analyst` | 2 | Triage findings, add notes, export data |
| `operator` | 3 | Run scans, manage clients, configure integrations |
| `admin` | 4 | User management, billing, SSO, tenant settings |
| `ceo` | 5 | CEO Mission Control, council streams, strategy |

**Superadmin** (`is_superadmin` flag) bypasses all role checks.

Special role **`agent`** — used by endpoint agents for WebSocket fleet APIs, not human RBAC ranks.

### Handler gates

Handlers call `require_role`, `require_operator`, `require_admin`, etc. at the top. Denied requests return **403 JSON** with reason.

Only **CEO or superadmin** may assign the `ceo` role to another user.

### Self-service paths (any authenticated user)

Includes `/api/auth/mfa/*`, `/api/auth/change-password`, `/api/account`, `/api/me`.

---

## Step-by-step: first admin login

### 1. Open Command Center

Navigate to `https://your-domain.example/command-center/login`.

### 2. Authenticate

```bash
curl -c cookies.txt -X POST https://your-domain.example/api/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@yourcompany.com","password":"YOUR_PASSWORD"}'
```

Response includes user profile and sets HttpOnly cookies.

### 3. Change default password

Command Center → Account → Change Password, or:

```
POST /api/auth/change-password
```

### 4. Create team users

Admin → Users → Invite. Assign minimum role required:

- SOC analysts → `analyst`
- Scan operators → `operator`
- Platform admins → `admin`

---

## Multi-factor authentication (MFA)

TOTP-based MFA via standard endpoints:

| Endpoint | Purpose |
|----------|---------|
| `POST /api/auth/mfa/setup` | Generate secret + QR provisioning URI |
| `POST /api/auth/mfa/enable` | Confirm TOTP and activate MFA |
| `POST /api/auth/mfa/verify` | Second factor during login |
| `POST /api/auth/mfa/disable` | Remove MFA (requires re-auth) |
| `GET /api/auth/mfa/status` | Check MFA state for current user |

Login lockout paths include `/api/login` and `/api/auth/mfa/verify` (Redis-backed). Token refresh (`/api/auth/refresh`) shares the pre-auth login rate-limit bucket so it cannot exhaust the `weissman_auth` pool.

**Procedure for new admins:**

1. Log in without MFA
2. Account → Security → Enable MFA
3. Scan QR with authenticator app
4. Store recovery codes per org policy
5. Verify logout/login with MFA challenge

---

## Session security

Production requirements (`security_startup.rs`):

- `WEISSMAN_ENV=production`
- `WEISSMAN_COOKIE_SECURE=1`
- JWT query param `?access_token=` rejected in production

Access token TTL: `WEISSMAN_ACCESS_TOKEN_MINUTES` (default 15, clamped 5–240).

Refresh TTL: `WEISSMAN_REFRESH_TOKEN_DAYS` (default 30).

---

## SSO integration

OIDC and SAML flows begin at:

- `GET /api/auth/oidc/begin`
- `GET /api/auth/saml/begin`
- `POST /api/auth/saml/acs`

Full IdP setup: manual **14**.

---

## Audit and compliance

- Login attempts, role changes, and destructive actions write to `audit_logs`
- Enable `WEISSMAN_LOG_FORMAT=json` for SIEM ingestion
- Review `/api/auth/me` role field when debugging 403 errors

---

## Verification

```bash
# Login succeeds
curl -sf -c /tmp/wc -X POST https://localhost/api/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"...","password":"..."}'

# Profile returns expected role
curl -sf -b /tmp/wc https://localhost/api/auth/me | jq .role

# Viewer cannot run scans (expect 403)
# Operator can POST /api/command-center/scan

# MFA status
curl -sf -b /tmp/wc https://localhost/api/auth/mfa/status
```

Test role boundaries in Command Center UI for each persona before go-live.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| 401 on all API calls | Expired JWT — refresh or re-login |
| 403 "role required" | User needs higher role; check Users admin |
| Account locked | Redis lockout after failed attempts — wait or admin reset |
| MFA loop | Clock skew on client; verify TOTP time sync |

See [17-troubleshooting](17-troubleshooting.md).

---

## Related manuals

- [05-production-security](05-production-security.md)
- [08-billing-multitenancy](08-billing-multitenancy.md)
- [09-client-onboarding](09-client-onboarding.md)
- [14-sso-identity](14-sso-identity.md)
